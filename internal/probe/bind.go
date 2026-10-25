package probe

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"

	"golang.zx2c4.com/wireguard/conn"
)

// udpBind is the probe's default conn.Bind: one UDP socket per family on a
// shared port, one packet per receive, and a fresh destination per send.
//
// It replaces conn.NewDefaultBind() because of an upstream bug in the pinned
// golang.zx2c4.com/wireguard v0.0.0-20261006164505-2631ce99a06f,
// conn/bind_std.go StdNetBind.Send (lines 366-376): the pooled *net.UDPAddr
// is resliced to ua.IP[:4] by an IPv4 send, and a later IPv6 send does
// copy(ua.IP, as16[:]), which copies only 4 bytes before reslicing to 16, so
// bytes 4-15 are left over from an earlier IPv6 destination (sendmmsg to
// fd00:231:: instead of fd00:231:3::1 was observed). The probe alternates
// endpoints and families every slot, so IPv6 endpoints would look mostly
// lossy.
//
// Remove udpBind once wireguard-go PR #135
// (https://github.com/WireGuard/wireguard-go/pull/135, which resizes ua.IP
// before the copy) is merged and a version containing it is pinned: run the
// send pattern of TestUDPBindAlternatingFamilies against conn.NewStdNetBind()
// (the pinned version loses nearly every IPv6 packet there), then let the
// probe default to conn.NewDefaultBind() and drop _WGGO_BIND_FIX from
// tests/integration/topology.py.
type udpBind struct {
	mu     sync.Mutex
	v4, v6 *net.UDPConn
}

func newUDPBind() *udpBind { return &udpBind{} }

// Open listens on port for IPv4 and IPv6 (either may be unsupported by the
// host). With port 0 both sockets share one random port, retrying like
// StdNetBind when the IPv6 side of a random IPv4 port is taken.
func (b *udpBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.v4 != nil || b.v6 != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	for tries := 0; ; tries++ {
		v4, p, err := listenUDP("udp4", port)
		if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
			return nil, 0, err
		}
		v6, p6, err := listenUDP("udp6", p)
		if port == 0 && p != 0 && errors.Is(err, syscall.EADDRINUSE) && tries < 100 {
			v4.Close()
			continue
		}
		if err != nil && !errors.Is(err, syscall.EAFNOSUPPORT) {
			if v4 != nil {
				v4.Close()
			}
			return nil, 0, err
		}
		var fns []conn.ReceiveFunc
		if v4 != nil {
			fns = append(fns, receiveFrom(v4))
		}
		if v6 != nil {
			fns = append(fns, receiveFrom(v6))
			p = p6
		}
		if len(fns) == 0 {
			return nil, 0, syscall.EAFNOSUPPORT
		}
		b.v4, b.v6 = v4, v6
		return fns, p, nil
	}
}

// listenUDP listens on the wildcard address of network ("udp6" sockets are
// IPv6-only in Go) and returns the actual port.
func listenUDP(network string, port uint16) (*net.UDPConn, uint16, error) {
	c, err := net.ListenUDP(network, &net.UDPAddr{Port: int(port)})
	if err != nil {
		return nil, 0, err
	}
	return c, c.LocalAddr().(*net.UDPAddr).AddrPort().Port(), nil
}

// receiveFrom returns a ReceiveFunc reading one datagram per call. Closing
// the socket unblocks it with net.ErrClosed, which ends wireguard-go's
// receive routine.
func receiveFrom(c *net.UDPConn) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, ap, err := c.ReadFromUDPAddrPort(packets[0])
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		eps[0] = &udpEndpoint{dst: unmap(ap)}
		return 1, nil
	}
}

// Close closes both sockets, unblocking the receivers.
func (b *udpBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	var err4, err6 error
	if b.v4 != nil {
		err4 = b.v4.Close()
	}
	if b.v6 != nil {
		err6 = b.v6.Close()
	}
	b.v4, b.v6 = nil, nil
	return errors.Join(err4, err6)
}

// SetMark sets SO_MARK on both sockets (needs CAP_NET_ADMIN). wireguard-go
// calls it after Open whenever the device's fwmark is nonzero.
func (b *udpBind) SetMark(mark uint32) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, c := range []*net.UDPConn{b.v4, b.v6} {
		if c == nil {
			continue
		}
		if err := setMark(c, mark); err != nil {
			return err
		}
	}
	return nil
}

// Send writes each buffer to ep through the socket of ep's family. The
// destination is passed by value on every call; nothing is shared between
// sends.
func (b *udpBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	e, ok := ep.(*udpEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	b.mu.Lock()
	c := b.v4
	if e.dst.Addr().Is6() {
		c = b.v6
	}
	b.mu.Unlock()
	if c == nil {
		return syscall.EAFNOSUPPORT
	}
	for _, buf := range bufs {
		if _, err := c.WriteToUDPAddrPort(buf, e.dst); err != nil {
			return err
		}
	}
	return nil
}

// ParseEndpoint parses ip:port or [ip]:port.
func (b *udpBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &udpEndpoint{dst: unmap(ap)}, nil
}

// unmap turns IPv4-mapped IPv6 into IPv4 (the IPv4 socket sends it) and
// keeps zones, which link-local destinations need.
func unmap(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// BatchSize is 1: the probe sends one packet per slot.
func (b *udpBind) BatchSize() int { return 1 }

// udpEndpoint is a destination without sticky source address.
type udpEndpoint struct {
	dst netip.AddrPort
}

func (e *udpEndpoint) ClearSrc()           {}
func (e *udpEndpoint) SrcToString() string { return "" }
func (e *udpEndpoint) DstToString() string { return e.dst.String() }
func (e *udpEndpoint) DstIP() netip.Addr   { return e.dst.Addr() }
func (e *udpEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

// DstToBytes is used for the cookie MAC2 computation.
func (e *udpEndpoint) DstToBytes() []byte {
	b, _ := e.dst.MarshalBinary()
	return b
}
