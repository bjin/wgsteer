// Package probe runs the measurement probe: an embedded wireguard-go device
// with roaming disabled, a channel TUN that crafts and parses ICMP/ICMPv6
// echo packets, and the slot scheduler that attributes replies to endpoints.
package probe

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/bjin/wgsteer/internal/endpoints"
	"github.com/bjin/wgsteer/internal/probecfg"
)

// replyQueueLen bounds replies waiting for the event loop.
const replyQueueLen = 64

// DefaultMTU is the probe device's MTU when Config.MTU is 0: WireGuard's
// default, which fits an IPv6 outer path on a 1500-byte link.
const DefaultMTU = 1420

// MaxMTU is the largest probe device MTU. wireguard-go pads a packet to at
// most the MTU and adds a 32-byte header and tag; the result must fit one UDP
// datagram over IPv4 (65535 - 20 - 8 = 65507 bytes), whatever the
// candidates' families. That gives 65475, below wireguard-go's own limit
// (device.MaxContentSize).
const MaxMTU = 65535 - 20 - 8 - device.MessageTransportSize

// MinMTU is the smallest probe device MTU for probes from src: the minimum
// IPv4 datagram size or the minimum IPv6 link MTU.
func MinMTU(src netip.Addr) int {
	if src.Unmap().Is4() {
		return 576
	}
	return 1280
}

// MaxPayloadSize is the largest ICMP payload of a probe from src that fits
// into mtu.
func MaxPayloadSize(mtu int, src netip.Addr) int {
	return mtu - ipHeaderLen(src.Unmap()) - icmpHeaderLen
}

// Config configures a Probe.
type Config struct {
	Identity    *probecfg.Config // already validated against ProbeAddr and Target
	ProbeAddr   netip.Addr       // source of the crafted echo requests
	Target      netip.Addr       // destination; replies are accepted only from it
	PayloadSize int              // ICMP payload bytes, MinPayloadSize to MaxPayloadSize(MTU)
	MTU         int              // probe device MTU (wireguard-go pads to it); 0 uses DefaultMTU
	Endpoint    netip.AddrPort   // initial endpoint (required: it disables roaming)
	Fwmark      uint32           // 0 leaves the socket unmarked
	Bind        conn.Bind        // nil uses the probe's own UDP bind (see udpBind)
	Logger      *slog.Logger     // nil uses slog.Default()

	// keepRoaming skips DisableSomeRoamingForBrokenMobileSemantics. Tests use
	// it as a negative control for the no-roam guarantee.
	keepRoaming bool
}

// Reply is a validated echo reply. SentAt and RecvAt are monotonic offsets
// since the probe started, stamped at TUN Read and TUN Write.
type Reply struct {
	Seq        uint16
	Nonce      uint64
	EndpointID uint32
	SentAt     time.Duration
	RecvAt     time.Duration
}

// RTT is the round-trip time measured at the WireGuard boundary.
func (r Reply) RTT() time.Duration { return r.RecvAt - r.SentAt }

// State is the probe's WireGuard state from IpcGet.
type State struct {
	Endpoint      netip.AddrPort // normalized; zero if unset
	LastHandshake time.Time      // zero if no handshake has completed
	ListenPort    uint16
	Fwmark        uint32
	RxBytes       uint64
	TxBytes       uint64
}

// Probe is the embedded wireguard-go probe device. Its methods are meant to
// be called from one goroutine (the daemon's event loop); Replies is fed
// from wireguard-go's receive path.
type Probe struct {
	dev         *device.Device
	bind        conn.Bind
	tun         *chanTUN
	replies     chan Reply
	peerHex     string
	publicKey   wgtypes.Key
	src, dst    netip.Addr
	ident       uint16
	payloadSize int
	closeOnce   sync.Once
}

// New creates the probe device, disables roaming, creates the peer with
// cfg.Endpoint in the same IpcSet, and brings the device up.
func New(cfg Config) (*Probe, error) {
	if cfg.Identity == nil {
		return nil, errors.New("probe identity is required")
	}
	src, dst := cfg.ProbeAddr.Unmap(), cfg.Target.Unmap()
	if !src.IsValid() || !dst.IsValid() {
		return nil, errors.New("probe address and target are required")
	}
	if src.Is4() != dst.Is4() {
		return nil, fmt.Errorf("probe address %s and target %s are different families", src, dst)
	}
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = DefaultMTU
	}
	if mtu < MinMTU(src) || mtu > MaxMTU {
		return nil, fmt.Errorf("probe MTU %d out of range [%d, %d]", mtu, MinMTU(src), MaxMTU)
	}
	if maxPayload := MaxPayloadSize(mtu, src); cfg.PayloadSize < MinPayloadSize || cfg.PayloadSize > maxPayload {
		return nil, fmt.Errorf("probe payload size %d out of range [%d, %d] for MTU %d", cfg.PayloadSize, MinPayloadSize, maxPayload, mtu)
	}
	ep := endpoints.Normalize(cfg.Endpoint)
	if !ep.IsValid() {
		return nil, errors.New("initial probe endpoint is required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	bind := cfg.Bind
	if bind == nil {
		bind = newUDPBind()
	}

	replies := make(chan Reply, replyQueueLen)
	ident := uint16(rand.Uint32())
	t := newChanTUN(time.Now(), dst, ident, mtu, replies, logger)
	dev := device.NewDevice(t, bind, wgLogger(logger))
	p := &Probe{
		dev:         dev,
		bind:        bind,
		tun:         t,
		replies:     replies,
		peerHex:     probecfg.HexKey(cfg.Identity.PeerKey),
		publicKey:   cfg.Identity.PublicKey,
		src:         src,
		dst:         dst,
		ident:       ident,
		payloadSize: cfg.PayloadSize,
	}
	// Order matters: roaming is disabled only for peers created afterwards
	// with an endpoint (uapi.go handlePostConfig evaluates
	// brokenRoaming && endpoint != nil at creation only).
	if !cfg.keepRoaming {
		dev.DisableSomeRoamingForBrokenMobileSemantics()
	}
	if err := dev.IpcSet(cfg.Identity.UAPI(ep, cfg.Fwmark)); err != nil {
		dev.Close()
		return nil, fmt.Errorf("configure probe device: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("bring probe device up: %w", err)
	}
	return p, nil
}

// wgLogger bridges wireguard-go logging to slog: verbose to debug, errors to
// warn. wireguard-go never logs key material beyond abbreviated public keys.
func wgLogger(l *slog.Logger) *device.Logger {
	return &device.Logger{
		Verbosef: func(format string, args ...any) {
			// Every slot retargets the peer; wireguard-go would log that
			// once per slot and drown the debug window (the daemon's own
			// sample line already names the endpoint).
			if format == "%v - UAPI: Updating endpoint" {
				return
			}
			if l.Enabled(context.Background(), slog.LevelDebug) {
				l.Debug(fmt.Sprintf(format, args...), "component", "wireguard-go")
			}
		},
		Errorf: func(format string, args ...any) {
			l.Warn(fmt.Sprintf(format, args...), "component", "wireguard-go")
		},
	}
}

// Retarget points the probe's peer at ep. It updates the existing peer and
// never re-creates it, so roaming stays disabled.
func (p *Probe) Retarget(ep netip.AddrPort) error {
	ep = endpoints.Normalize(ep)
	if !ep.IsValid() {
		return errors.New("retarget probe: invalid endpoint")
	}
	if err := p.dev.IpcSet("public_key=" + p.peerHex + "\nendpoint=" + ep.String() + "\n"); err != nil {
		return fmt.Errorf("retarget probe to %s: %w", ep, err)
	}
	return nil
}

// SetFwmark sets the fwmark of the probe's UDP sockets (needs CAP_NET_ADMIN
// when nonzero). wireguard-go's BindSetMark records a new mark before it
// applies it to the bind and skips a mark equal to the recorded one, so after
// a failed application a retry with the same mark would succeed without
// touching the sockets. SetFwmark therefore also applies the mark to the bind
// itself; setting a mark twice is harmless.
func (p *Probe) SetFwmark(mark uint32) error {
	if err := p.dev.IpcSet("fwmark=" + strconv.FormatUint(uint64(mark), 10) + "\n"); err != nil {
		return fmt.Errorf("set probe fwmark %d: %w", mark, err)
	}
	if err := p.bind.SetMark(mark); err != nil {
		return fmt.Errorf("set probe fwmark %d: %w", mark, err)
	}
	return nil
}

// Send crafts one echo request and queues it for wireguard-go without
// blocking. The send time is stamped when wireguard-go reads the packet.
func (p *Probe) Send(seq uint16, nonce uint64, endpointID uint32) error {
	pkt := buildEcho(p.src, p.dst, echoFields{ID: p.ident, Seq: seq, Nonce: nonce, EndpointID: endpointID}, p.payloadSize)
	if err := p.tun.enqueue(pkt); err != nil {
		return fmt.Errorf("send probe seq %d: %w", seq, err)
	}
	return nil
}

// Replies delivers validated echo replies (source, type and identifier
// checked). Seq and nonce are matched by the Scheduler. The channel is never
// closed.
func (p *Probe) Replies() <-chan Reply { return p.replies }

// PublicKey is the probe's own public key.
func (p *Probe) PublicKey() wgtypes.Key { return p.publicKey }

// State reads the probe's device and peer state via IpcGet.
func (p *Probe) State() (State, error) {
	raw, err := p.dev.IpcGet()
	if err != nil {
		return State{}, fmt.Errorf("read probe state: %w", err)
	}
	return parseState(raw)
}

// parseState parses IpcGet output of a device with at most one peer.
func parseState(raw string) (State, error) {
	var (
		st         State
		sec, nsec  int64
		haveHSTime bool
	)
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		key, value, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		var err error
		switch key {
		case "listen_port":
			var v uint64
			v, err = strconv.ParseUint(value, 10, 16)
			st.ListenPort = uint16(v)
		case "fwmark":
			var v uint64
			v, err = strconv.ParseUint(value, 10, 32)
			st.Fwmark = uint32(v)
		case "endpoint":
			var ap netip.AddrPort
			ap, err = netip.ParseAddrPort(value)
			st.Endpoint = endpoints.Normalize(ap)
		case "last_handshake_time_sec":
			sec, err = strconv.ParseInt(value, 10, 64)
			haveHSTime = true
		case "last_handshake_time_nsec":
			nsec, err = strconv.ParseInt(value, 10, 64)
		case "rx_bytes":
			st.RxBytes, err = strconv.ParseUint(value, 10, 64)
		case "tx_bytes":
			st.TxBytes, err = strconv.ParseUint(value, 10, 64)
		}
		if err != nil {
			return State{}, fmt.Errorf("parse probe state %s: %w", key, err)
		}
	}
	if err := sc.Err(); err != nil {
		return State{}, fmt.Errorf("parse probe state: %w", err)
	}
	if haveHSTime && (sec != 0 || nsec != 0) {
		st.LastHandshake = time.Unix(sec, nsec)
	}
	return st, nil
}

// Close shuts the device down and closes its sockets. It is idempotent.
func (p *Probe) Close() error {
	p.closeOnce.Do(p.dev.Close)
	return nil
}
