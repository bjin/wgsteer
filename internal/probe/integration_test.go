package probe

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/bjin/wgsteer/internal/endpoints"
	"github.com/bjin/wgsteer/internal/probecfg"
)

// The probe under test, a wireguard-go server (roaming on) with
// an ICMP echo responder, and UDP relays between them, all on loopback.
// Timings are scaled down from the 1 s / 500 ms defaults.
const (
	itInterval = 60 * time.Millisecond
	itTimeout  = 40 * time.Millisecond
)

// relay forwards UDP between one client (the probe) and the server, like a
// relay VPS: the server sees the relay's upstream socket as the peer's
// endpoint. Delay, loss and blackhole apply to the downstream direction
// (server to probe); blackhole also drops upstream.
type relay struct {
	addr      netip.AddrPort
	ln, up    *net.UDPConn
	client    atomic.Pointer[netip.AddrPort]
	delay     atomic.Int64 // downstream delay in ns
	dropEvery atomic.Int64 // drop every Nth downstream data packet (0: none)
	blackhole atomic.Bool
	dataDown  int64 // downstream data packets seen; downstream goroutine only
}

// newRelay listens on host (an ephemeral port) and forwards to the server
// over IPv4 loopback.
func newRelay(t *testing.T, host netip.Addr, server netip.AddrPort) *relay {
	t.Helper()
	ln, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(host, 0)))
	if err != nil {
		t.Fatal(err)
	}
	up, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(server))
	if err != nil {
		ln.Close()
		t.Fatal(err)
	}
	r := &relay{addr: endpoints.Normalize(ln.LocalAddr().(*net.UDPAddr).AddrPort()), ln: ln, up: up}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); r.upstream() }()
	go func() { defer wg.Done(); r.downstream() }()
	t.Cleanup(func() {
		ln.Close()
		up.Close()
		wg.Wait()
	})
	return r
}

func (r *relay) upstream() {
	buf := make([]byte, 2048)
	for {
		n, from, err := r.ln.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		r.client.Store(&from)
		if r.blackhole.Load() {
			continue
		}
		r.up.Write(buf[:n])
	}
}

func (r *relay) downstream() {
	buf := make([]byte, 2048)
	for {
		n, err := r.up.Read(buf)
		if err != nil {
			return
		}
		client := r.client.Load()
		if client == nil || r.blackhole.Load() {
			continue
		}
		// WireGuard transport data: type 4, longer than a bare keepalive.
		if n > 32 && buf[0] == 4 {
			r.dataDown++
			if every := r.dropEvery.Load(); every > 0 && r.dataDown%every == 0 {
				continue
			}
		}
		pkt := slices.Clone(buf[:n])
		if d := time.Duration(r.delay.Load()); d > 0 {
			time.AfterFunc(d, func() { r.ln.WriteToUDPAddrPort(pkt, *client) })
		} else {
			r.ln.WriteToUDPAddrPort(pkt, *client)
		}
	}
}

// startServer runs a wireguard-go server (roaming on) for the probe peer
// with an echo responder on its channel TUN, and returns its UDP address.
// onInbound, if set, sees every packet the server decrypts.
func startServer(t *testing.T, serverKey, probePub wgtypes.Key, probeAddr netip.Addr, onInbound func([]byte)) netip.AddrPort {
	t.Helper()
	ct := tuntest.NewChannelTUN()
	dev := device.NewDevice(ct.TUN(), conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	done := make(chan struct{})
	t.Cleanup(func() {
		close(done)
		dev.Close()
	})
	go func() {
		for {
			select {
			case <-done:
				return
			case pkt := <-ct.Inbound:
				if onInbound != nil {
					onInbound(pkt)
				}
				reply, ok := echoReply(pkt)
				if !ok {
					continue
				}
				select {
				case ct.Outbound <- reply:
				case <-done:
					return
				}
			}
		}
	}()
	cfg := fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nallowed_ip=%s\n",
		probecfg.HexKey(serverKey), probecfg.HexKey(probePub), netip.PrefixFrom(probeAddr, probeAddr.BitLen()))
	if err := dev.IpcSet(cfg); err != nil {
		t.Fatal(err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	raw, err := dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	st, err := parseState(raw)
	if err != nil || st.ListenPort == 0 {
		t.Fatalf("server listen port: %v %+v", err, st)
	}
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), st.ListenPort)
}

// testNet is the loopback integration setup plus a slot loop shaped like the daemon's.
type testNet struct {
	t      *testing.T
	probe  *Probe
	relays []*relay
	list   []netip.AddrPort
	sched  *Scheduler
	slots  map[uint16]Slot // every slot begun, by seq
}

// loopback4 returns n relay hosts on 127.0.0.1.
func loopback4(n int) []netip.Addr {
	return slices.Repeat([]netip.Addr{netip.MustParseAddr("127.0.0.1")}, n)
}

func newTestNet(t *testing.T, inner string, relayHosts []netip.Addr, keepRoaming bool) *testNet {
	t.Helper()
	probeAddr, target := v4Probe, v4Target
	if inner == "v6" {
		probeAddr, target = v6Probe, v6Target
	}
	serverKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	probeKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	server := startServer(t, serverKey, probeKey.PublicKey(), probeAddr, nil)

	n := &testNet{t: t, sched: NewScheduler(itTimeout, nil), slots: make(map[uint16]Slot)}
	for _, host := range relayHosts {
		r := newRelay(t, host, server)
		n.relays = append(n.relays, r)
		n.list = append(n.list, r.addr)
	}
	id := &probecfg.Config{PrivateKey: probeKey, PublicKey: probeKey.PublicKey(), PeerKey: serverKey.PublicKey()}
	if err := id.Validate(probeAddr, target); err != nil {
		t.Fatal(err)
	}
	n.probe, err = New(Config{
		Identity:    id,
		ProbeAddr:   probeAddr,
		Target:      target,
		PayloadSize: 56,
		Endpoint:    n.list[0],
		Logger:      slog.New(slog.DiscardHandler),
		keepRoaming: keepRoaming,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.probe.Close() })
	return n
}

// The largest accepted MTU and payload must give a sendable outer packet:
// a MaxMTU inner packet becomes a 65507-byte WireGuard message, the IPv4
// UDP payload limit. The probe sends straight to the server (the relays'
// buffers are small) and the server must decrypt the full-size packet.
func TestLargestProbeIsSendable(t *testing.T) {
	serverKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	probeKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	sizes := make(chan int, 16)
	server := startServer(t, serverKey, probeKey.PublicKey(), v4Probe, func(pkt []byte) {
		select {
		case sizes <- len(pkt):
		default:
		}
	})
	id := &probecfg.Config{PrivateKey: probeKey, PublicKey: probeKey.PublicKey(), PeerKey: serverKey.PublicKey()}
	if err := id.Validate(v4Probe, v4Target); err != nil {
		t.Fatal(err)
	}
	p, err := New(Config{Identity: id, ProbeAddr: v4Probe, Target: v4Target, MTU: MaxMTU,
		PayloadSize: MaxPayloadSize(MaxMTU, v4Probe), Endpoint: server, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	deadline := time.After(10 * time.Second)
	for seq := uint16(1); ; seq++ {
		// The first echo waits for the handshake; send again until one arrives.
		if err := p.Send(seq, uint64(seq), 1); err != nil {
			t.Fatal(err)
		}
		select {
		case n := <-sizes:
			if n != MaxMTU {
				t.Fatalf("server decrypted %d bytes, want the full %d", n, MaxMTU)
			}
			return
		case <-time.After(200 * time.Millisecond):
		case <-deadline:
			t.Fatal("no full-size probe reached the server: the outer packet does not fit a UDP datagram")
		}
	}
}

// run drives n slots on a fixed schedule: Begin with the session validity
// from IpcGet, retarget, send, match replies until the deadline, Finish,
// then idle until the slot ends. Replies that do not match the pending slot
// go to unmatched together with the current slot.
func (n *testNet) run(slots int, unmatched func(cur Slot, r Reply)) []Result {
	t := n.t
	t.Helper()
	var results []Result
	base := time.Now()
	for i := range slots {
		start := base.Add(time.Duration(i) * itInterval)
		if d := time.Until(start); d > 0 {
			time.Sleep(d) // wait for the slot boundary (pacing, not synchronization)
		}
		now := time.Now()
		st, err := n.probe.State()
		if err != nil {
			t.Fatal(err)
		}
		slot := n.sched.Begin(n.list, now, SessionValid(st.LastHandshake, now))
		n.slots[slot.Seq] = slot
		if err := n.probe.Retarget(slot.Endpoint); err != nil {
			t.Fatal(err)
		}
		if err := n.probe.Send(slot.Seq, slot.Nonce, slot.EndpointID); err != nil {
			t.Fatal(err)
		}
		handle := func(r Reply) {
			if !n.sched.Match(r) && unmatched != nil {
				unmatched(slot, r)
			}
		}
		deadline := time.NewTimer(time.Until(slot.Deadline))
	wait:
		for {
			select {
			case r := <-n.probe.Replies():
				handle(r)
			case <-deadline.C:
				break wait
			}
		}
		// Replies already delivered when the deadline fired still count.
		for drained := false; !drained; {
			select {
			case r := <-n.probe.Replies():
				handle(r)
			default:
				drained = true
			}
		}
		res, ok := n.sched.Finish()
		if !ok {
			t.Fatal("no pending slot")
		}
		results = append(results, res)
		idle := time.NewTimer(time.Until(start.Add(itInterval)))
	rest:
		for {
			select {
			case r := <-n.probe.Replies():
				handle(r)
			case <-idle.C:
				break rest
			}
		}
	}
	return results
}

// stallBudget is the number of losses tolerated on a loss-free path: a
// scheduler stall over the 40 ms timeout (race detector, parallel tests)
// turns a reply into a loss, which is the intended semantics but not what
// these tests are about.
const stallBudget = 1

// startup runs slots until the first valid sample, i.e. until the first
// handshake has completed, and returns the slots before it, which must be
// invalid: a probe sent without a session is never a loss. The first
// handshake takes a load-dependent number of slots, so the measured phases
// start afterwards.
func (n *testNet) startup() []Result {
	t := n.t
	t.Helper()
	var before []Result
	for range 200 {
		res := n.run(1, nil)[0]
		if res.Valid {
			if len(before) == 0 {
				t.Fatalf("first slot (before any handshake) is valid: %+v", res)
			}
			return before
		}
		before = append(before, res)
	}
	t.Fatal("no handshake within 200 slots")
	return nil
}

// requireValid asserts that the session stayed usable for every sample.
func requireValid(t *testing.T, results []Result) {
	t.Helper()
	for _, r := range results {
		if !r.Valid {
			t.Fatalf("invalid sample after the first handshake: %+v", r)
		}
	}
}

// byEndpoint splits the valid results per endpoint.
func byEndpoint(results []Result) map[netip.AddrPort][]Result {
	m := make(map[netip.AddrPort][]Result)
	for _, r := range results {
		if r.Valid {
			m[r.Endpoint] = append(m[r.Endpoint], r)
		}
	}
	return m
}

func rtts(rs []Result) []time.Duration {
	var out []time.Duration
	for _, r := range rs {
		if r.Replied {
			out = append(out, r.RTT)
		}
	}
	slices.Sort(out)
	return out
}

func losses(rs []Result) int {
	n := 0
	for _, r := range rs {
		if !r.Replied {
			n++
		}
	}
	return n
}

func TestIntegrationRTTAndLoss(t *testing.T) {
	t.Parallel()
	for _, inner := range []string{"v4", "v6"} {
		t.Run(inner, func(t *testing.T) {
			t.Parallel()
			n := newTestNet(t, inner, loopback4(3), false)
			n.relays[1].delay.Store(int64(15 * time.Millisecond))
			n.relays[2].delay.Store(int64(5 * time.Millisecond))
			n.relays[2].dropEvery.Store(2)

			n.startup()
			const rounds = 10
			results := n.run(rounds*len(n.list), nil)
			requireValid(t, results)
			per := byEndpoint(results)

			// Per-relay RTT tracks the injected delay.
			r0, r1, r2 := rtts(per[n.list[0]]), rtts(per[n.list[1]]), rtts(per[n.list[2]])
			if len(r0) == 0 || len(r1) == 0 || len(r2) == 0 {
				t.Fatalf("relays without replies: %v %v %v", r0, r1, r2)
			}
			med := func(d []time.Duration) time.Duration { return d[len(d)/2] }
			if m := med(r0); m >= 10*time.Millisecond {
				t.Errorf("relay 0 (no delay): median RTT %v", m)
			}
			if r1[0] < 15*time.Millisecond || med(r1) >= 30*time.Millisecond {
				t.Errorf("relay 1 (15 ms): RTTs %v", r1)
			}
			if r2[0] < 5*time.Millisecond || med(r2) >= 20*time.Millisecond {
				t.Errorf("relay 2 (5 ms): RTTs %v", r2)
			}
			if med(r1)-med(r0) < 10*time.Millisecond {
				t.Errorf("relay 1 median %v not ~15 ms above relay 0 median %v", med(r1), med(r0))
			}
			t.Logf("RTTs: relay 0 %v; relay 1 %v; relay 2 %v", r0, r1, r2)

			// Loss is attributed to the lossy relay only.
			if l := losses(per[n.list[0]]) + losses(per[n.list[1]]); l > stallBudget {
				t.Errorf("%d losses on loss-free relays", l)
			}
			k := len(per[n.list[2]])
			if l := losses(per[n.list[2]]); l < k/2-1 || l > (k+1)/2+1+stallBudget {
				t.Errorf("relay 2 (drops every 2nd reply): %d losses of %d", l, k)
			}
		})
	}
}

func TestIntegrationLateReplyDoesNotRoam(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		keepRoaming bool
	}{
		{"roaming disabled", false},
		// Negative control: without DisableSomeRoamingForBrokenMobileSemantics
		// the same late reply moves the endpoint, so the check has teeth.
		{"control roaming enabled", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			n := newTestNet(t, "v4", loopback4(2), tc.keepRoaming)
			late, other := n.list[0], n.list[1]
			// Relay 0 replies arrive 90 ms after the send: past the 40 ms
			// timeout, in the middle of relay 1's slot [60 ms, 120 ms).
			n.relays[0].delay.Store(int64(90 * time.Millisecond))

			var observed []netip.AddrPort
			// The first slot's echo is staged until the handshake via relay 0
			// completes (>= 90 ms): no reply within the timeout, yet invalid
			// rather than lost.
			if pre := n.startup(); pre[0].Replied {
				t.Errorf("startup slot %+v, want unanswered", pre[0])
			}
			results := n.run(12, func(cur Slot, r Reply) {
				orig, ok := n.slots[r.Seq]
				if !ok || orig.Nonce != r.Nonce || orig.Endpoint != late || !orig.Valid || cur.Endpoint != other {
					return
				}
				st, err := n.probe.State()
				if err != nil {
					t.Fatal(err)
				}
				observed = append(observed, st.Endpoint)
			})

			requireValid(t, results)
			per := byEndpoint(results)
			if len(per[late]) != 6 || len(per[other]) != 6 {
				t.Fatalf("samples: %d late, %d other", len(per[late]), len(per[other]))
			}
			if l := losses(per[late]); l != len(per[late]) {
				t.Errorf("late relay: %d losses of %d valid samples, want all", l, len(per[late]))
			}
			if l := losses(per[other]); l > stallBudget {
				t.Errorf("other relay: %d losses", l)
			}
			if len(observed) < 3 {
				t.Fatalf("only %d late replies observed during the other relay's slot", len(observed))
			}
			want := other
			if tc.keepRoaming {
				want = late
			}
			for i, ep := range observed {
				if ep != want {
					t.Errorf("late reply %d: probe endpoint %v, want %v", i, ep, want)
				}
			}
		})
	}
}

func TestIntegrationBlackholeSessionSurvives(t *testing.T) {
	t.Parallel()
	n := newTestNet(t, "v4", loopback4(3), false)
	slots := 4 * len(n.list)

	n.startup()
	warm := n.run(slots, nil)
	requireValid(t, warm)
	if l := losses(warm); l > stallBudget {
		t.Errorf("warm-up: %d losses", l)
	}

	n.relays[1].blackhole.Store(true)
	dark := n.run(slots, nil)
	for _, r := range dark {
		if !r.Valid {
			t.Fatalf("session lost while one relay is blackholed: %+v", r)
		}
	}
	per := byEndpoint(dark)
	if l := losses(per[n.list[1]]); l != len(per[n.list[1]]) {
		t.Errorf("blackholed relay: %d losses of %d, want all", l, len(per[n.list[1]]))
	}
	if l := losses(per[n.list[0]]) + losses(per[n.list[2]]); l > stallBudget {
		t.Errorf("other relays while one is blackholed: %d losses", l)
	}

	n.relays[1].blackhole.Store(false)
	restored := n.run(slots, nil)
	requireValid(t, restored)
	if l := losses(restored); l > stallBudget {
		t.Errorf("after restoring the relay: %d losses", l)
	}
}

// TestIntegrationMixedFamilies alternates IPv4 and IPv6 endpoints in the
// pattern that corrupts IPv6 destinations in the pinned upstream
// StdNetBind (see udpBind): an IPv6 endpoint (a dead one in the RFC 6666
// discard prefix), then IPv4, then the IPv6 relay on ::1. Every relay must
// answer; only the dead endpoint loses.
func TestIntegrationMixedFamilies(t *testing.T) {
	t.Parallel()
	c, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	c.Close()
	v4, v6 := netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")
	n := newTestNet(t, "v4", []netip.Addr{v4, v4, v6}, false)
	dead := netip.MustParseAddrPort(discardV6)
	n.list = slices.Insert(n.list, 1, dead) // v4, dead v6, v4, ::1

	n.startup()
	const rounds = 10
	results := n.run(rounds*len(n.list), nil)
	requireValid(t, results)
	per := byEndpoint(results)
	for i, ep := range n.list {
		if len(per[ep]) != rounds {
			t.Fatalf("endpoint %d (%v): %d samples, want %d", i, ep, len(per[ep]), rounds)
		}
	}
	if l := losses(per[dead]); l != rounds {
		t.Errorf("dead endpoint: %d losses of %d", l, rounds)
	}
	if l := losses(per[n.list[3]]); l > stallBudget {
		t.Errorf("IPv6 relay %v: %d losses of %d", n.list[3], l, rounds)
	}
	if l := losses(per[n.list[0]]) + losses(per[n.list[2]]); l > stallBudget {
		t.Errorf("IPv4 relays: %d losses", l)
	}
}
