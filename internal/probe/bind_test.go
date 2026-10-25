package probe

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

func openTestBind(t *testing.T) (*udpBind, []conn.ReceiveFunc, uint16) {
	t.Helper()
	b := newUDPBind()
	fns, port, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	if port == 0 {
		t.Fatal("Open(0) returned port 0")
	}
	return b, fns, port
}

func listenLoopback(t *testing.T, network string, ip net.IP) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP(network, &net.UDPAddr{IP: ip})
	if err != nil {
		t.Skipf("no %s loopback: %v", network, err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// discardV6 is in the RFC 6666 discard-only prefix 100::/64, with nonzero
// bytes past the first four. A send to it leaves those bytes in the
// upstream StdNetBind's pooled address, so a following IPv4 send and then
// an IPv6 send to ::1 would go to ::1:2:3:4 instead (see udpBind).
const discardV6 = "[100::1:2:3:4]:9"

// TestUDPBindAlternatingFamilies sends to IPv4 and IPv6 loopback in
// alternation, each IPv6 send preceded by a send to a different IPv6
// address and an IPv4 send: the IPv6 destination must arrive intact, and
// both families share the bind's port.
func TestUDPBindAlternatingFamilies(t *testing.T) {
	b, fns, port := openTestBind(t)
	if len(fns) != 2 {
		t.Fatalf("%d receive functions, want 2 (IPv4 and IPv6)", len(fns))
	}
	l4 := listenLoopback(t, "udp4", net.IPv4(127, 0, 0, 1))
	l6 := listenLoopback(t, "udp6", net.IPv6loopback)
	discard, err := b.ParseEndpoint(discardV6)
	if err != nil {
		t.Fatal(err)
	}

	for i, l := range []*net.UDPConn{l4, l6, l4, l6, l4, l6} {
		if l == l4 {
			// Prime the next IPv6 send with another IPv6 destination. The
			// discard prefix may be unroutable here; only address handling
			// matters.
			_ = b.Send([][]byte{{0}}, discard)
		}
		ep, err := b.ParseEndpoint(l.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		msg := fmt.Appendf(nil, "packet %d", i)
		if err := b.Send([][]byte{msg}, ep); err != nil {
			t.Fatalf("send %d (%v): %v", i, ep.DstToString(), err)
		}
		l.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 64)
		n, from, err := l.ReadFromUDPAddrPort(buf)
		if err != nil {
			t.Fatalf("packet %d not received on %v: %v", i, l.LocalAddr(), err)
		}
		if string(buf[:n]) != string(msg) {
			t.Errorf("listener %v got %q, want %q", l.LocalAddr(), buf[:n], msg)
		}
		if from.Port() != port {
			t.Errorf("packet %d sent from port %d, want the bind's port %d", i, from.Port(), port)
		}
	}

	// Receive path: one datagram per call, source as the endpoint.
	for i, l := range []*net.UDPConn{l4, l6} {
		dst := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)
		if i == 1 {
			dst = netip.AddrPortFrom(netip.IPv6Loopback(), port)
		}
		if _, err := l.WriteToUDPAddrPort([]byte("reply"), dst); err != nil {
			t.Fatal(err)
		}
		bufs := [][]byte{make([]byte, 64)}
		sizes := []int{0}
		eps := []conn.Endpoint{nil}
		n, err := fns[i](bufs, sizes, eps)
		if err != nil || n != 1 || string(bufs[0][:sizes[0]]) != "reply" {
			t.Fatalf("receive %d: n=%d err=%v data=%q", i, n, err, bufs[0][:sizes[0]])
		}
		if got, want := eps[0].DstToString(), l.LocalAddr().String(); got != want {
			t.Errorf("receive %d: endpoint %s, want %s", i, got, want)
		}
	}
}

func TestUDPBindLifecycle(t *testing.T) {
	b, fns, port := openTestBind(t)
	if _, _, err := b.Open(0); !errors.Is(err, conn.ErrBindAlreadyOpen) {
		t.Errorf("second Open = %v, want ErrBindAlreadyOpen", err)
	}
	if err := b.Send([][]byte{{1}}, &conn.StdNetEndpoint{}); !errors.Is(err, conn.ErrWrongEndpointType) {
		t.Errorf("Send with a foreign endpoint = %v", err)
	}

	done := make(chan error, len(fns))
	for _, fn := range fns {
		go func() {
			_, err := fn([][]byte{make([]byte, 64)}, []int{0}, []conn.Endpoint{nil})
			done <- err
		}()
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	for range fns {
		if err := <-done; !errors.Is(err, net.ErrClosed) {
			t.Errorf("receive after Close = %v, want net.ErrClosed", err)
		}
	}

	// Reopen on the same explicit port.
	fns, got, err := b.Open(port)
	if err != nil || got != port || len(fns) == 0 {
		t.Fatalf("reopen on %d: port %d, %d fns, %v", port, got, len(fns), err)
	}
}

func TestUDPBindParseEndpoint(t *testing.T) {
	b := newUDPBind()
	for in, want := range map[string]string{
		"192.0.2.1:51820":          "192.0.2.1:51820",
		"[2001:DB8:0::1]:443":      "[2001:db8::1]:443",
		"[::ffff:192.0.2.1]:51820": "192.0.2.1:51820",
		"[fe80::1%eth0]:51820":     "[fe80::1%eth0]:51820",
	} {
		ep, err := b.ParseEndpoint(in)
		if err != nil {
			t.Errorf("ParseEndpoint(%q): %v", in, err)
			continue
		}
		if got := ep.DstToString(); got != want {
			t.Errorf("ParseEndpoint(%q) = %s, want %s", in, got, want)
		}
	}
	for _, bad := range []string{"", "example.com:1", "192.0.2.1", "2001:db8::1:443"} {
		if _, err := b.ParseEndpoint(bad); err == nil {
			t.Errorf("ParseEndpoint(%q) accepted", bad)
		}
	}
}
