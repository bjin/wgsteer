package daemon

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/bjin/wgsteer/internal/endpoints"
	"github.com/bjin/wgsteer/internal/nftable"
	"github.com/bjin/wgsteer/internal/policy"
	"github.com/bjin/wgsteer/internal/probe"
	"github.com/bjin/wgsteer/internal/probecfg"
	"github.com/bjin/wgsteer/internal/status"
	"github.com/bjin/wgsteer/internal/wgdev"
)

var (
	epA = netip.MustParseAddrPort("10.0.0.1:4000")
	epB = netip.MustParseAddrPort("10.0.0.2:4000")
	epC = netip.MustParseAddrPort("[fd00::3]:4000")
	epU = netip.MustParseAddrPort("10.0.0.9:4000") // unlisted
)

const (
	testInterval = 100 * time.Millisecond
	testTimeout  = 50 * time.Millisecond
	testPort     = 51820
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time { return c.t }

// events records the order of device and nft writes across fakes.
type events []string

type setCall struct {
	ep        netip.AddrPort
	keepalive time.Duration
	kick      bool
}

type fakeDev struct {
	ev    *events
	dev   *wgdev.Device // nil: not found
	sets  []setCall
	apply bool // SetEndpoint changes the device like wgdev's netlink calls do
	// failStep makes the next SetEndpoint fail at that netlink call
	// (1-based), with the calls before it applied.
	failStep int
}

func (f *fakeDev) Get(name string) (*wgdev.Device, error) {
	if f.dev == nil {
		return nil, fmt.Errorf("get %s: %w", name, wgdev.ErrNotFound)
	}
	c := *f.dev
	c.Peers = slices.Clone(f.dev.Peers)
	return &c, nil
}

// SetEndpoint mirrors the netlink calls of wgdev.SetEndpoint.
func (f *fakeDev) SetEndpoint(name string, peer wgtypes.Key, ep netip.AddrPort, keepalive time.Duration, kick bool) error {
	*f.ev = append(*f.ev, "set "+ep.String())
	f.sets = append(f.sets, setCall{ep, keepalive, kick})
	type call struct {
		ep netip.AddrPort
		ka *time.Duration
	}
	calls := []call{{ep: ep}}
	switch {
	case kick && keepalive > 0:
		calls = []call{{ep, new(time.Duration(0))}, {ka: new(keepalive)}}
	case kick:
		calls = []call{{ep, new(time.Duration(0))}, {ka: new(time.Second)}, {ka: new(time.Duration(0))}}
	}
	for i, c := range calls {
		if f.failStep == i+1 {
			f.failStep = 0
			return fmt.Errorf("fake netlink call %d failed", i+1)
		}
		if !f.apply {
			continue
		}
		if c.ep.IsValid() {
			f.dev.Peers[0].Endpoint = c.ep
		}
		if c.ka != nil {
			f.dev.Peers[0].Keepalive = *c.ka
		}
	}
	return nil
}

func (f *fakeDev) Close() error { return nil }

type fakeNFT struct {
	ev         *events
	applies    []nftable.Ruleset
	errs       []error // returned by the next Apply calls, in order
	committed  nftable.Ruleset
	reconnects []nftable.Ruleset
	closed     bool
}

func (f *fakeNFT) Info() nftable.TableInfo {
	return nftable.TableInfo{Name: "wgsteer_wg0", Chain: "input", OwnerFlag: true, Owner: 42}
}

func (f *fakeNFT) Apply(rs nftable.Ruleset) ([]nftable.Counter, error) {
	*f.ev = append(*f.ev, "apply")
	f.applies = append(f.applies, rs)
	if len(f.errs) > 0 {
		err := f.errs[0]
		f.errs = f.errs[1:]
		if err != nil {
			return nil, err
		}
	}
	f.committed = rs
	return nil, nil
}

func (f *fakeNFT) Committed() nftable.Ruleset { return f.committed }

func (f *fakeNFT) Counters() ([]nftable.Counter, error) { return nil, nil }

func (f *fakeNFT) Reconnect(rs nftable.Ruleset) error {
	f.reconnects = append(f.reconnects, rs)
	f.committed = rs
	return nil
}

func (f *fakeNFT) Close() error { f.closed = true; return nil }

func (f *fakeNFT) last() nftable.Ruleset { return f.applies[len(f.applies)-1] }

type fakeProbe struct {
	replies   chan probe.Reply
	ep        netip.AddrPort
	marks     []uint32 // SetFwmark calls
	markErrs  []error  // results of the next SetFwmark calls
	handshake func() time.Time
	seq       uint16
	nonce     uint64
	id        uint32
	key       wgtypes.Key
}

func (p *fakeProbe) Retarget(ep netip.AddrPort) error { p.ep = ep; return nil }
func (p *fakeProbe) SetFwmark(m uint32) error {
	p.marks = append(p.marks, m)
	if len(p.markErrs) == 0 {
		return nil
	}
	err := p.markErrs[0]
	p.markErrs = p.markErrs[1:]
	return err
}
func (p *fakeProbe) Send(seq uint16, nonce uint64, id uint32) error {
	p.seq, p.nonce, p.id = seq, nonce, id
	return nil
}
func (p *fakeProbe) Replies() <-chan probe.Reply { return p.replies }
func (p *fakeProbe) State() (probe.State, error) {
	return probe.State{Endpoint: p.ep, LastHandshake: p.handshake(), ListenPort: 40000}, nil
}
func (p *fakeProbe) PublicKey() wgtypes.Key { return p.key }
func (p *fakeProbe) Close() error           { return nil }

type harness struct {
	t     *testing.T
	d     *daemon
	clk   *fakeClock
	ev    events
	dev   *fakeDev
	nft   *fakeNFT
	prb   *fakeProbe
	opens int
	logs  *bytes.Buffer
	// rtt is each endpoint's probe RTT; a missing endpoint loses every probe.
	rtt map[netip.AddrPort]time.Duration
}

func key(t *testing.T) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func testConfig() Config {
	c := DefaultConfig()
	c.Device, c.NftTable = "wg0", "wgsteer_wg0"
	c.ProbeAddr, c.Target = netip.MustParseAddr("192.0.2.3"), netip.MustParseAddr("192.0.2.1")
	c.ProbeInterval, c.ProbeTimeout = testInterval, testTimeout
	c.History, c.MinSamples, c.HalfLife = 50, 5, 3
	c.Persist, c.Cooldown, c.WaitToRestore = time.Second, 0, 0
	c.LogLevel = slog.LevelDebug
	return c
}

// newHarness starts a daemon with fakes on a device whose managed peer is
// on devEP (keepalive 25 s), with list as the endpoint list.
func newHarness(t *testing.T, cfg Config, list []netip.AddrPort, devEP netip.AddrPort) *harness {
	t.Helper()
	priv, peerKey, devKey := key(t), key(t), key(t)
	h := &harness{t: t, clk: &fakeClock{t: time.Unix(1000, 0)}, logs: &bytes.Buffer{},
		rtt: map[netip.AddrPort]time.Duration{}}
	wallBase := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	clockBase := h.clk.t
	wall := func() time.Time { return wallBase.Add(h.clk.t.Sub(clockBase)) }
	h.dev = &fakeDev{ev: &h.ev, apply: true, dev: &wgdev.Device{
		Name: "wg0", Type: "kernel", PublicKey: devKey.PublicKey(), ListenPort: testPort,
		Peers: []wgdev.Peer{{PublicKey: peerKey.PublicKey(), Endpoint: devEP, Keepalive: 25 * time.Second,
			LastHandshake: wall().Add(-time.Second)}},
	}}
	h.nft = &fakeNFT{ev: &h.ev}
	h.prb = &fakeProbe{replies: make(chan probe.Reply, 4), key: priv.PublicKey(),
		handshake: func() time.Time { return wall().Add(-time.Second) }}
	dp := deps{
		dev: h.dev,
		openNFT: func(string) (Firewall, error) {
			h.opens++
			return h.nft, nil
		},
		newProbe: func(probe.Config) (Prober, error) { return h.prb, nil },
	}
	h.d = newDaemon(cfg, NewLogging(h.logs, cfg.LogLevel), h.clk, wall, NewHeartbeat(time.Now()), dp)
	h.d.setList(endpoints.Unnamed(list))
	h.d.ident = &probecfg.Config{PrivateKey: priv, PublicKey: priv.PublicKey(), PeerKey: peerKey.PublicKey()}
	dev, err := h.dev.Get("wg0")
	if err != nil {
		t.Fatal(err)
	}
	peer, wait, err := h.d.inspect(dev, nil)
	if wait != "" || err != nil {
		t.Fatalf("inspect: %q %v", wait, err)
	}
	if err := h.d.setup(dev, peer); err != nil {
		t.Fatal(err)
	}
	return h
}

// slot runs one probe slot through the real scheduler and policy tick.
func (h *harness) slot() {
	h.t.Helper()
	if _, ok := h.d.beginSlot(h.clk.Now()); !ok {
		h.t.Fatal("slot not started")
	}
	if rtt, ok := h.rtt[h.prb.ep]; ok {
		h.prb.replies <- probe.Reply{Seq: h.prb.seq, Nonce: h.prb.nonce, EndpointID: h.prb.id, RecvAt: rtt}
	}
	h.clk.t = h.clk.t.Add(testTimeout)
	h.d.finishSlot(h.clk.Now())
	h.clk.t = h.clk.t.Add(testInterval - testTimeout)
}

// slotsUntil runs slots until cond holds, failing after limit slots.
func (h *harness) slotsUntil(limit int, desc string, cond func() bool) {
	h.t.Helper()
	for range limit {
		h.slot()
		if cond() {
			return
		}
	}
	h.t.Fatalf("no %s after %d slots", desc, limit)
}

func (h *harness) reconcile() { h.d.reconcile(h.clk.Now()) }

func (h *harness) count(msg string) int {
	return strings.Count(h.logs.String(), "msg=\""+msg+"\"") + strings.Count(h.logs.String(), "msg="+msg+" ")
}

func (h *harness) degradeRule() policy.RuleState {
	for _, r := range h.d.decision.Record.Rules {
		if r.Rule == policy.RuleDegrade {
			return r
		}
	}
	h.t.Fatal("no degrade rule in the last record")
	return policy.RuleState{}
}

func denies(rs nftable.Ruleset, eps ...netip.AddrPort) bool {
	got := slices.Clone(rs.Denied)
	want := slices.Clone(eps)
	cmp := func(a, b netip.AddrPort) int { return a.Compare(b) }
	slices.SortFunc(got, cmp)
	slices.SortFunc(want, cmp)
	return slices.Equal(got, want)
}

// A (#0, selected) at 40 ms, B (#1) at 10 ms: a degradation switch to B
// fires once both are eligible and --persist has accumulated.
func degradeHarness(t *testing.T, cfg Config) *harness {
	h := newHarness(t, cfg, []netip.AddrPort{epA, epB}, epA)
	h.rtt[epA], h.rtt[epB] = 40*time.Millisecond, 10*time.Millisecond
	return h
}

func TestSwitchAbortKeepsStateAndRetries(t *testing.T) {
	for _, tc := range []struct {
		name      string
		err       error
		reconnect bool
	}{
		{"rejected", fmt.Errorf("apply: %w", nftable.ErrRejected), false},
		{"unknown, mismatching read-back", fmt.Errorf("apply: %w", nftable.ErrRejected), false},
		{"unknown, read-back failed", fmt.Errorf("apply: %w", nftable.ErrUnknown), false},
		{"connection broken", fmt.Errorf("apply: %w", nftable.ErrConnBroken), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := degradeHarness(t, testConfig())
			preSwitch := h.nft.last()
			h.nft.errs = []error{tc.err}
			h.slotsUntil(100, "switch attempt", func() bool { return len(h.nft.applies) == 2 })

			if len(h.dev.sets) != 0 {
				t.Fatalf("device endpoint set after a failed commit: %v", h.dev.sets)
			}
			if got := h.d.eng.Selected(); got != epA {
				t.Fatalf("selection = %v, want %v unchanged", got, epA)
			}
			if r := h.degradeRule(); !r.Fired || r.Value != r.Hold {
				t.Fatalf("degrade accumulator not kept at its hold: %+v", r)
			}
			last := h.d.history[len(h.d.history)-1]
			if last.Result != status.ResultAborted || last.To != epB {
				t.Fatalf("history = %+v, want an aborted switch to %v", last, epB)
			}
			if h.count("switch aborted") != 1 {
				t.Fatalf("want one switch aborted log:\n%s", h.logs)
			}
			if tc.reconnect {
				if len(h.nft.reconnects) != 1 || !h.nft.reconnects[0].Equal(preSwitch) {
					t.Fatalf("reconnects = %v, want the pre-switch rules %v", h.nft.reconnects, preSwitch)
				}
			} else if len(h.nft.reconnects) != 0 {
				t.Fatalf("unexpected reconnect: %v", h.nft.reconnects)
			}

			// The accumulator was kept, so the very next tick retries.
			h.slot()
			if len(h.dev.sets) != 1 || h.dev.sets[0].ep != epB {
				t.Fatalf("retry: sets = %v, want one set to %v", h.dev.sets, epB)
			}
			if got := h.d.eng.Selected(); got != epB {
				t.Fatalf("retry: selection = %v, want %v", got, epB)
			}
		})
	}
}

func TestSwitchBlocksThenSets(t *testing.T) {
	h := degradeHarness(t, testConfig())
	h.ev = nil
	h.slotsUntil(100, "switch", func() bool { return len(h.dev.sets) > 0 })
	if !slices.Equal(h.ev, []string{"apply", "set " + epB.String()}) {
		t.Fatalf("write order = %v, want nft apply then set", h.ev)
	}
	if !denies(h.nft.last(), epA) || h.nft.last().ListenPort != testPort {
		t.Fatalf("switch rules = %+v, want only %v denied on port %d", h.nft.last(), epA, testPort)
	}
	if got := h.dev.sets[0]; got != (setCall{epB, 25 * time.Second, true}) {
		t.Fatalf("set = %+v, want %v with the peer's keepalive and a kick", got, epB)
	}
	if h.d.eng.Selected() != epB || h.count("switch") != 1 {
		t.Fatalf("selection %v, logs:\n%s", h.d.eng.Selected(), h.logs)
	}
	h.reconcile()
	if h.count("switch verified") != 1 || h.d.verified == nil || !*h.d.verified {
		t.Fatalf("switch not verified:\n%s", h.logs)
	}
}

func TestReassertOncePerTick(t *testing.T) {
	h := newHarness(t, testConfig(), []netip.AddrPort{epA, epB}, epA)
	h.dev.apply = false // the device stays on B, like a stubborn external reset
	h.dev.dev.Peers[0].Endpoint = epB
	h.reconcile()
	if len(h.dev.sets) != 1 || h.dev.sets[0].ep != epA || !h.dev.sets[0].kick {
		t.Fatalf("sets = %v, want one kicked re-assert to %v", h.dev.sets, epA)
	}
	h.reconcile()
	if len(h.dev.sets) != 2 {
		t.Fatalf("sets = %v, want one re-assert per tick", h.dev.sets)
	}
	if h.count("re-assert") != 2 || len(h.nft.applies) != 1 {
		t.Fatalf("re-assert must not touch nft (applies %d):\n%s", len(h.nft.applies), h.logs)
	}
}

// Late packets from the alias of the endpoint just left can roam the device
// back to it. That alias is denied, so it must be re-asserted, not learned
// as an alias of the new selection.
func TestRoamBackToDeniedAliasReasserted(t *testing.T) {
	h := degradeHarness(t, testConfig())
	h.dev.dev.Peers[0].Endpoint = epU // A answers from U
	h.reconcile()
	h.slotsUntil(100, "switch to B", func() bool { return h.d.eng.Selected() == epB })
	if !denies(h.nft.last(), epA, epU) || h.dev.dev.Peers[0].Endpoint != epB {
		t.Fatalf("after the switch: rules %v, device on %v", h.nft.last().Denied, h.dev.dev.Peers[0].Endpoint)
	}
	h.dev.dev.Peers[0].Endpoint = epU // a queued packet from U arrives after the switch
	n := len(h.dev.sets)
	h.reconcile()
	if len(h.dev.sets) != n+1 || h.dev.sets[n].ep != epB || h.count("alias learned") != 1 {
		t.Fatalf("writes %v, alias learned %d; logs:\n%s", h.dev.sets[n:], h.count("alias learned"), h.logs)
	}
	if h.dev.dev.Peers[0].Endpoint != epB || !denies(h.nft.last(), epA, epU) {
		t.Fatalf("device on %v, rules %v", h.dev.dev.Peers[0].Endpoint, h.nft.last().Denied)
	}
}

func TestAliasesDeniedOnlyAfterSwitchingAway(t *testing.T) {
	h := degradeHarness(t, testConfig())
	h.dev.dev.Peers[0].Endpoint = epU
	h.reconcile()
	h.reconcile()
	if len(h.dev.sets) != 0 {
		t.Fatalf("alias re-asserted: %v", h.dev.sets)
	}
	if h.count("alias learned") != 1 || !slices.Equal(h.d.aliases, []netip.AddrPort{epU}) {
		t.Fatalf("aliases %v, logs:\n%s", h.d.aliases, h.logs)
	}
	if len(h.nft.applies) != 1 || !denies(h.nft.last(), epB) {
		t.Fatalf("alias changed the rules: %+v", h.nft.applies)
	}

	h.slotsUntil(100, "switch to B", func() bool { return h.d.eng.Selected() == epB })
	if !denies(h.nft.last(), epA, epU) {
		t.Fatalf("switching away denied %v, want %v and its alias %v", h.nft.last().Denied, epA, epU)
	}

	// B degrades; the switch back rebuilds the set from scratch.
	h.rtt[epA], h.rtt[epB] = 10*time.Millisecond, 40*time.Millisecond
	h.slotsUntil(200, "switch back to A", func() bool { return h.d.eng.Selected() == epA })
	if !denies(h.nft.last(), epB) {
		t.Fatalf("rules after switching back = %v, want only %v", h.nft.last().Denied, epB)
	}
}

// wg0 starts on the unlisted U: no selection, all listed denied, U allowed.
// The startup switch has no previous selection whose aliases it could
// retire, so U stays allowed (it may be the target's own reply address).
func TestStartupOnUnlistedKeepsStartEndpointAllowed(t *testing.T) {
	h := newHarness(t, testConfig(), []netip.AddrPort{epA, epB}, epU)
	if h.d.eng.Selected().IsValid() {
		t.Fatalf("selection = %v, want none", h.d.eng.Selected())
	}
	if len(h.nft.applies) != 1 || !denies(h.nft.applies[0], epA, epB) {
		t.Fatalf("startup rules = %+v, want all listed denied", h.nft.applies)
	}
	h.rtt[epB] = 10 * time.Millisecond // only B is eligible: the startup switch goes there
	h.slotsUntil(100, "startup switch", func() bool { return len(h.dev.sets) > 0 })
	if h.dev.sets[0].ep != epB || !denies(h.nft.last(), epA) {
		t.Fatalf("startup switch set %v with rules %v; want %v, denying only %v (the start endpoint %v stays allowed)",
			h.dev.sets[0].ep, h.nft.last().Denied, epB, epA, epU)
	}

	// B answers from U, so wg0 roams there: U is learned as B's alias,
	// neither fought nor denied.
	h.dev.dev.Peers[0].Endpoint = epU
	applies := len(h.nft.applies)
	h.reconcile()
	h.reconcile()
	if len(h.dev.sets) != 1 || len(h.nft.applies) != applies {
		t.Fatalf("alias of the new selection was fought: sets %v, rules %v", h.dev.sets, h.nft.applies[applies:])
	}
	if !slices.Equal(h.d.aliases, []netip.AddrPort{epU}) || h.count("alias learned") != 1 {
		t.Fatalf("aliases %v, want %v learned under %v; logs:\n%s", h.d.aliases, epU, epB, h.logs)
	}

	// Switching away from B retires B and its learned alias U.
	h.rtt[epA], h.rtt[epB] = 10*time.Millisecond, 40*time.Millisecond
	h.slotsUntil(300, "switch to A", func() bool { return h.d.eng.Selected() == epA })
	if !denies(h.nft.last(), epB, epU) {
		t.Fatalf("rules after leaving %v = %v, want %v and its alias %v", epB, h.nft.last().Denied, epB, epU)
	}
}

func TestListenPortChangeRebuilds(t *testing.T) {
	h := newHarness(t, testConfig(), []netip.AddrPort{epA, epB}, epA)
	h.dev.dev.ListenPort = 51999
	h.dev.dev.Peers[0].Endpoint = epB // recreated device back on its configured default
	h.reconcile()
	if len(h.nft.applies) != 2 || h.nft.last().ListenPort != 51999 || !denies(h.nft.last(), epB) {
		t.Fatalf("rules = %+v, want a rebuild on port 51999", h.nft.applies)
	}
	if h.count("nft rebuild") != 1 || len(h.dev.sets) != 1 || h.dev.sets[0].ep != epA {
		t.Fatalf("want a rebuild then a re-assert to %v; sets %v\n%s", epA, h.dev.sets, h.logs)
	}
	if h.ev[len(h.ev)-2] != "apply" {
		t.Fatalf("re-assert before the rebuild: %v", h.ev)
	}
}

func TestFwmarkChangeReachesProbe(t *testing.T) {
	h := newHarness(t, testConfig(), []netip.AddrPort{epA, epB}, epA)
	h.dev.dev.Fwmark = 51820
	h.prb.markErrs = []error{errors.New("sockets refused the mark")}
	h.reconcile() // fails
	h.reconcile() // the same mark again: must be retried, not taken as applied
	h.reconcile() // applied: nothing more to do
	if !slices.Equal(h.prb.marks, []uint32{51820, 51820}) {
		t.Fatalf("probe fwmark calls = %v, want a failed and a retried 51820", h.prb.marks)
	}
	if h.count("fwmark changed") != 1 || h.count("probe fwmark failed") != 1 {
		t.Fatalf("logs:\n%s", h.logs)
	}
}

// A partly applied mark (IPv4 took B, IPv6 failed) leaves the sockets in an
// unknown state: when the device returns to the last good mark, it must be
// applied again rather than assumed.
func TestFwmarkRetriedAfterRevertToLastGood(t *testing.T) {
	h := newHarness(t, testConfig(), []netip.AddrPort{epA, epB}, epA)
	h.dev.dev.Fwmark = 51820
	h.prb.markErrs = []error{errors.New("IPv6 socket refused the mark")}
	h.reconcile() // B fails part-way
	h.dev.dev.Fwmark = 0
	h.reconcile() // back to the last good mark: re-applied
	h.reconcile() // settled
	if !slices.Equal(h.prb.marks, []uint32{51820, 0}) {
		t.Fatalf("probe fwmark calls = %v, want a failed 51820 then 0 re-applied", h.prb.marks)
	}
}

// A switch write that fails after the endpoint landed leaves the kick's
// temporary keepalive (0) on the device. Reconcile must redo the write with
// the original keepalive, never adopt the temporary value, and verify the
// switch only on a read after the write completed.
func TestPartialSwitchWriteRestoresKeepalive(t *testing.T) {
	h := degradeHarness(t, testConfig())
	h.dev.failStep = 2 // endpoint and keepalive 0 applied; restoring 25 s fails
	h.slotsUntil(100, "switch to B", func() bool { return h.d.eng.Selected() == epB })
	if p := h.dev.dev.Peers[0]; p.Endpoint != epB || p.Keepalive != 0 || h.count("switch set endpoint failed") != 1 {
		t.Fatalf("after the failed write: peer %+v; logs:\n%s", p, h.logs)
	}
	want := setCall{epB, 25 * time.Second, true}
	h.dev.failStep = 2 // the first retry fails the same way
	h.reconcile()
	if got := h.dev.sets[len(h.dev.sets)-1]; got != want || h.count("switch verified") != 0 {
		t.Fatalf("first retry %+v (want %+v), verified %d", got, want, h.count("switch verified"))
	}
	h.reconcile()
	if got := h.dev.sets[len(h.dev.sets)-1]; got != want || h.dev.dev.Peers[0].Keepalive != 25*time.Second {
		t.Fatalf("second retry %+v, device keepalive %v", got, h.dev.dev.Peers[0].Keepalive)
	}
	if h.count("endpoint write resumed") != 1 || h.count("switch verified") != 0 {
		t.Fatalf("verified on the write's own tick, before reading the result; logs:\n%s", h.logs)
	}
	n := len(h.dev.sets)
	h.reconcile() // the read shows endpoint B and keepalive 25 s
	if len(h.dev.sets) != n || h.count("switch verified") != 1 {
		t.Fatalf("after the confirming read: extra writes %v, verified %d", h.dev.sets[n:], h.count("switch verified"))
	}
}

// A switch write that fails before the endpoint is set leaves the device on
// the old selection's alias. While the write is redone, that alias must not
// be learned as the new selection's alias (it stays denied) and must not be
// re-asserted on top of the retry.
func TestFailedSwitchWriteKeepsOldAliasDenied(t *testing.T) {
	h := degradeHarness(t, testConfig())
	h.dev.dev.Peers[0].Endpoint = epU // A answers from U
	h.reconcile()
	h.dev.failStep = 1 // nothing applied
	h.slotsUntil(100, "switch to B", func() bool { return h.d.eng.Selected() == epB })
	if !denies(h.nft.last(), epA, epU) || h.dev.dev.Peers[0].Endpoint != epU {
		t.Fatalf("rules %v, device on %v", h.nft.last().Denied, h.dev.dev.Peers[0].Endpoint)
	}
	n := len(h.dev.sets)
	h.dev.failStep = 1
	h.reconcile() // the retry fails again; the device still shows U
	if len(h.dev.sets) != n+1 || h.count("alias learned") != 1 || h.count("re-assert") != 0 {
		t.Fatalf("writes %v, alias learned %d, re-asserts %d; logs:\n%s",
			h.dev.sets[n:], h.count("alias learned"), h.count("re-assert"), h.logs)
	}
	h.reconcile() // the retry lands on B
	h.reconcile() // read: B with keepalive 25 s
	if h.dev.dev.Peers[0].Endpoint != epB || h.count("switch verified") != 1 || !denies(h.nft.last(), epA, epU) {
		t.Fatalf("device on %v, verified %d, rules %v", h.dev.dev.Peers[0].Endpoint, h.count("switch verified"), h.nft.last().Denied)
	}
}

// A retry that the device reports as done but that does not stick (the
// endpoint stays where it was) must not count as verified; the next read
// re-asserts instead.
func TestRetriedWriteVerifiedOnlyOnRead(t *testing.T) {
	h := degradeHarness(t, testConfig())
	h.dev.failStep = 1
	h.slotsUntil(100, "switch to B", func() bool { return h.d.eng.Selected() == epB })
	h.dev.apply = false // later writes do not move the device
	h.reconcile()       // the retry "succeeds"
	if h.count("endpoint write resumed") != 1 || h.count("switch verified") != 0 {
		t.Fatalf("logs:\n%s", h.logs)
	}
	h.reconcile() // the read still shows A
	if h.count("switch verified") != 0 || h.count("re-assert") != 1 {
		t.Fatalf("verified %d, re-asserts %d; logs:\n%s", h.count("switch verified"), h.count("re-assert"), h.logs)
	}
}

// With an original keepalive of 0 the kick sets 1 s and then 0; a failure
// at the last call leaves 1 s, which must be reset to 0.
func TestPartialReassertRestoresZeroKeepalive(t *testing.T) {
	h := newHarness(t, testConfig(), []netip.AddrPort{epA, epB}, epA)
	h.dev.dev.Peers[0].Keepalive = 0
	h.reconcile()
	h.dev.dev.Peers[0].Endpoint = epB // external reset
	h.dev.failStep = 3                // endpoint and the 1 s kick applied; restoring 0 fails
	h.reconcile()
	if p := h.dev.dev.Peers[0]; p.Endpoint != epA || p.Keepalive != time.Second || h.count("re-assert failed") != 1 {
		t.Fatalf("after the failed re-assert: peer %+v; logs:\n%s", p, h.logs)
	}
	h.reconcile()
	if got := h.dev.sets[len(h.dev.sets)-1]; got != (setCall{epA, 0, true}) || h.dev.dev.Peers[0].Keepalive != 0 {
		t.Fatalf("retry %+v, device keepalive %v", got, h.dev.dev.Peers[0].Keepalive)
	}
}

// A keepalive that is neither the original nor the kick's temporary value
// means the device was reconfigured meanwhile: that configuration wins, and
// later writes restore it instead of the old original.
func TestPendingWriteSupersededByReconfiguration(t *testing.T) {
	h := newHarness(t, testConfig(), []netip.AddrPort{epA, epB}, epA)
	h.dev.dev.Peers[0].Endpoint = epB
	h.dev.failStep = 2
	h.reconcile() // the re-assert lands on A but leaves keepalive 0
	// netifd reconfigures the peer: its own keepalive, its default endpoint.
	h.dev.dev.Peers[0].Keepalive, h.dev.dev.Peers[0].Endpoint = 15*time.Second, epB
	h.reconcile()
	if got := h.dev.sets[len(h.dev.sets)-1]; got != (setCall{epA, 15 * time.Second, true}) {
		t.Fatalf("write after the reconfiguration %+v, want A with the new 15s keepalive", got)
	}
	if h.count("endpoint write superseded") != 1 || h.dev.dev.Peers[0].Keepalive != 15*time.Second {
		t.Fatalf("device keepalive %v; logs:\n%s", h.dev.dev.Peers[0].Keepalive, h.logs)
	}
}

func TestDeviceMissingDetaches(t *testing.T) {
	h := degradeHarness(t, testConfig())
	saved := h.dev.dev
	h.dev.dev = nil
	h.reconcile()
	h.reconcile()
	if h.d.state != status.StateDetached || h.count("device detached") != 1 {
		t.Fatalf("state %v, logs:\n%s", h.d.state, h.logs)
	}
	// Probing continues and a due switch waits; nft is left alone.
	for range 40 {
		h.slot()
	}
	if len(h.nft.applies) != 1 || h.nft.closed || len(h.dev.sets) != 0 {
		t.Fatalf("detached daemon touched nft or the device: applies %d closed %v sets %v",
			len(h.nft.applies), h.nft.closed, h.dev.sets)
	}
	if h.d.decision.Record.Endpoints[1].Samples == 0 {
		t.Fatal("probing stopped while detached")
	}

	h.dev.dev = saved
	h.reconcile()
	if h.d.state != status.StateRunning || h.count("device attached") != 1 {
		t.Fatalf("state %v after reappearing:\n%s", h.d.state, h.logs)
	}
	h.slotsUntil(5, "deferred switch", func() bool { return len(h.dev.sets) > 0 })
}

func TestDryRunNeverWrites(t *testing.T) {
	cfg := testConfig()
	cfg.DryRun = true
	h := degradeHarness(t, cfg)
	h.dev.dev.Peers[0].Endpoint = epB
	h.reconcile()
	h.slotsUntil(100, "simulated switch", func() bool { return h.d.eng.Selected() == epB })
	h.dev.dev.Peers[0].Endpoint = epA
	h.reconcile()
	if h.opens != 0 || len(h.nft.applies) != 0 || len(h.dev.sets) != 0 {
		t.Fatalf("dry-run wrote: nft opens %d applies %d sets %v", h.opens, len(h.nft.applies), h.dev.sets)
	}
	if h.count("would switch") != 1 || h.d.history[0].Result != status.ResultDryRun {
		t.Fatalf("history %+v, logs:\n%s", h.d.history, h.logs)
	}
	if s := h.d.snap.Load(); s.NFT.Enabled || !s.Daemon.DryRun {
		t.Fatalf("snapshot nft %+v daemon %+v", s.NFT, s.Daemon)
	}
}

func TestReloadRemovingSelectionSwitchesAtOnce(t *testing.T) {
	cfg := testConfig()
	cfg.Cooldown = time.Hour // rule 6 ignores it
	cfg.Endpoints = filepath.Join(t.TempDir(), "endpoints")
	h := newHarness(t, cfg, []netip.AddrPort{epA, epB, epC}, epA)
	for _, ep := range []netip.AddrPort{epA, epB, epC} {
		h.rtt[ep] = 10 * time.Millisecond
	}
	for range 30 {
		h.slot()
	}
	if len(h.dev.sets) != 0 {
		t.Fatalf("unexpected switch: %v", h.dev.sets)
	}
	if err := os.WriteFile(cfg.Endpoints, []byte(epB.String()+"\n"+epC.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.d.reload(h.clk.Now())
	if len(h.dev.sets) != 1 || h.dev.sets[0].ep != epB {
		t.Fatalf("sets = %v, want an immediate switch to %v", h.dev.sets, epB)
	}
	if last := h.d.history[len(h.d.history)-1]; last.Kind != policy.KindReload {
		t.Fatalf("switch kind = %v, want reload", last.Kind)
	}
	// The rebuild after the reload keeps the removed selection allowed; the
	// switch then denies it like an alias.
	if n := len(h.nft.applies); !denies(h.nft.applies[n-2], epB, epC) || !denies(h.nft.last(), epC, epA) {
		t.Fatalf("rules = %+v", h.nft.applies)
	}
}

// TestReloadRenamesAndReorders: names follow the list; an unnamed endpoint
// is named by its new index.
func TestReloadRenamesAndReorders(t *testing.T) {
	cfg := testConfig()
	cfg.Cooldown = time.Hour
	cfg.Endpoints = filepath.Join(t.TempDir(), "endpoints")
	h := newHarness(t, cfg, []netip.AddrPort{epA, epB, epC}, epA)
	for _, ep := range []netip.AddrPort{epA, epB, epC} {
		h.rtt[ep] = 10 * time.Millisecond
	}
	h.slot()
	list := epC.String() + " # far\n" + epA.String() + " #  us \n" + epB.String() + " #\n"
	if err := os.WriteFile(cfg.Endpoints, []byte(list), 0o600); err != nil {
		t.Fatal(err)
	}
	h.d.reload(h.clk.Now())
	h.slot()
	h.d.publish()
	s := h.d.snap.Load()
	if s.Selection.Endpoint != epA || s.Selection.Index != 1 || s.Selection.Name != "us" {
		t.Fatalf("selection %+v", s.Selection)
	}
	var names []string
	for _, e := range s.Endpoints {
		names = append(names, e.Name)
	}
	if got := strings.Join(names, " "); got != "far us 2" {
		t.Fatalf("endpoint names %q", got)
	}
	if sl := s.Probe.Slot; sl == nil || sl.Name != endpoints.DisplayName(h.d.eps[sl.Index].Name, sl.Index) {
		t.Fatalf("slot %+v", sl)
	}
}

func TestSnapshotIsComplete(t *testing.T) {
	h := degradeHarness(t, testConfig())
	h.slotsUntil(100, "switch", func() bool { return len(h.dev.sets) > 0 })
	h.reconcile()
	h.d.publish()
	s := h.d.snap.Load()
	if s.Daemon.State != status.StateRunning || s.Selection.Endpoint != epB || s.Selection.Index != 1 {
		t.Fatalf("selection %+v", s.Selection)
	}
	if len(s.Endpoints) != 2 || !s.Endpoints[0].Denied || s.Endpoints[0].Last == nil {
		t.Fatalf("endpoints %+v", s.Endpoints)
	}
	if s.Selection.LastSwitch == nil || s.Selection.LastSwitch.Result != status.ResultOK || len(s.History) != 1 {
		t.Fatalf("history %+v", s.History)
	}
	// Loop-clock times are converted to wall time.
	if y := s.Endpoints[0].Last.At.Year(); y != 2026 {
		t.Fatalf("sample time %v is not wall time", s.Endpoints[0].Last.At)
	}
	if !s.NFT.Enabled || !s.NFT.InSync || s.Device.Endpoint != epB || !s.Device.Listed {
		t.Fatalf("nft %+v device %+v", s.NFT, s.Device)
	}
	h.logs.Reset()
	h.d.dump()
	if h.count("status") < 8 {
		t.Fatalf("status dump too short:\n%s", h.logs)
	}
}

func TestStartupRejectsForeignPeer(t *testing.T) {
	h := newHarness(t, testConfig(), []netip.AddrPort{epA}, epA)
	dev, _ := h.dev.Get("wg0")
	dev.Peers[0].PublicKey = key(t).PublicKey()
	_, wait, err := h.d.inspect(dev, nil)
	if err == nil || wait == "" {
		t.Fatalf("inspect accepted a device without the probe's peer")
	}
	if _, wait, err := h.d.inspect(nil, fmt.Errorf("x: %w", wgdev.ErrNotFound)); err != nil || wait == "" {
		t.Fatalf("missing device: wait %q err %v", wait, err)
	}
	if !errors.Is(&StartupError{Step: "x", Err: wgdev.ErrNotFound}, wgdev.ErrNotFound) {
		t.Fatal("StartupError does not unwrap")
	}
}
