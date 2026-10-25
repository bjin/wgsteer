package policy

import (
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/bjin/wgsteer/internal/stats"
)

// fastParams makes the estimate follow the newest sample (half-life of a
// quarter sample) and turns the noise gate, loss weight, jitter and order
// bias off unless a test sets them, so every condition is controlled by
// single probes.
func fastParams() Params {
	return Params{
		Interval:      time.Second,
		Persist:       10 * time.Second,
		Cooldown:      0,
		WaitToRestore: 20 * time.Second,
		MarginAbs:     0,
		History:       8,
		MinSamples:    2,
		HalfLife:      0.25,
		NoiseGate:     0,
		LossWeight:    0,
		JitterWeight:  0,
		OrderBias:     0,
		Margin:        0.15,
		OutageEpsilon: 1e-5,
	}
}

var t0 = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)

type fixture struct {
	t     *testing.T
	e     *Engine
	addrs []netip.AddrPort
	now   time.Time
	last  Decision
}

// newFixture creates an engine over n endpoints with selection sel (-1 for
// none) at t0.
func newFixture(t *testing.T, p Params, n, sel int) *fixture {
	t.Helper()
	f := &fixture{t: t, addrs: simAddrs(n), now: t0}
	var s netip.AddrPort
	if sel >= 0 {
		s = f.addrs[sel]
	}
	e, err := New(p, f.addrs, s, t0)
	if err != nil {
		t.Fatal(err)
	}
	f.e = e
	return f
}

const lost = -1

// probe records one sample for endpoint i (rtt in ms, lost for a loss) sent
// at the current time, advances one interval and ticks.
func (f *fixture) probe(i int, rttMS float64) Decision {
	s := stats.Sample{At: f.now}
	if rttMS >= 0 {
		s.Replied, s.RTT = true, time.Duration(rttMS*float64(time.Millisecond))
	}
	f.e.Record(f.addrs[i], s)
	f.now = f.now.Add(f.e.p.Interval)
	f.last = f.e.Tick(f.now)
	return f.last
}

// cycle probes every endpoint once in list order with the given RTTs and
// returns the first switch proposed (without committing) or the last
// decision.
func (f *fixture) cycle(rtts ...float64) Decision {
	f.t.Helper()
	if len(rtts) != len(f.addrs) {
		f.t.Fatalf("cycle needs %d rtts", len(f.addrs))
	}
	var d Decision
	for i, r := range rtts {
		d = f.probe(i, r)
		if d.Switch {
			return d
		}
	}
	return d
}

func (f *fixture) commit(d Decision) {
	f.t.Helper()
	if !d.Switch {
		f.t.Fatalf("commit of a non-switch: %s", d.Reason)
	}
	f.e.Commit(d, f.now)
}

func (f *fixture) idx(ap netip.AddrPort) int {
	for i, a := range f.addrs {
		if a == ap {
			return i
		}
	}
	return -1
}

func rule(d Decision, name string, target netip.AddrPort) RuleState {
	for _, r := range d.Record.Rules {
		if r.Rule == name && (!target.IsValid() || r.Target == target) {
			return r
		}
	}
	return RuleState{}
}

func wantSwitch(t *testing.T, d Decision, kind Kind, to netip.AddrPort) {
	t.Helper()
	if !d.Switch || d.Kind != kind || d.To != to {
		t.Fatalf("want %s switch to %v, got switch=%v kind=%s to=%v blocker=%s: %s", kind, to, d.Switch, d.Kind, d.To, d.Blocker, d.Reason)
	}
}

func wantBlocked(t *testing.T, d Decision, b Blocker, reasonPrefix string) {
	t.Helper()
	if d.Switch || d.Blocker != b || !strings.HasPrefix(d.Reason, reasonPrefix) {
		t.Fatalf("want blocker %s with reason %q…, got switch=%v blocker=%s reason %q", b, reasonPrefix, d.Switch, d.Blocker, d.Reason)
	}
}

func TestStep(t *testing.T) {
	s := time.Second
	for _, c := range []struct {
		acc, dt   time.Duration
		cond      bool
		limit, ok time.Duration
	}{
		{0, s, true, 10 * s, s},
		{9 * s, 2 * s, true, 10 * s, 10 * s}, // clamp at T
		{10 * s, s, false, 10 * s, 9 * s},    // drains, never restarts
		{s, 2 * s, false, 10 * s, 0},         // clamp at 0
		{12 * s, 0, true, 10 * s, 10 * s},    // shrunk limit
	} {
		if got := step(c.acc, c.dt, c.cond, c.limit); got != c.ok {
			t.Errorf("step(%v,%v,%v,%v) = %v, want %v", c.acc, c.dt, c.cond, c.limit, got, c.ok)
		}
	}
}

func TestNewAndValidate(t *testing.T) {
	p := DefaultParams()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	addrs := simAddrs(2)
	if _, err := New(p, nil, netip.AddrPort{}, t0); err == nil {
		t.Error("empty list accepted")
	}
	if _, err := New(p, []netip.AddrPort{addrs[0], addrs[0]}, netip.AddrPort{}, t0); err == nil {
		t.Error("duplicate accepted")
	}
	if _, err := New(p, addrs[:1], addrs[1], t0); err == nil {
		t.Error("unlisted selection accepted")
	}
	mapped := netip.AddrPortFrom(netip.AddrFrom16(addrs[1].Addr().As16()), addrs[1].Port())
	e, err := New(p, addrs, mapped, t0)
	if err != nil || e.Selected() != addrs[1] {
		t.Errorf("mapped selection: %v %v", e.Selected(), err)
	}
	bad := []func(*Params){
		func(p *Params) { p.Interval = 0 },
		func(p *Params) { p.MinSamples = p.History + 1 },
		func(p *Params) { p.HalfLife = 0 },
		func(p *Params) { p.HalfLife = math.NaN() },
		func(p *Params) { p.OutageEpsilon = 1 },
		func(p *Params) { p.Cooldown = -1 },
	}
	for i, mod := range bad {
		q := DefaultParams()
		mod(&q)
		if q.Validate() == nil {
			t.Errorf("bad params #%d accepted", i)
		}
		if _, err := New(q, addrs, netip.AddrPort{}, t0); err == nil {
			t.Errorf("New with bad params #%d accepted", i)
		}
	}
}

func TestInvalidSamplesExcluded(t *testing.T) {
	f := newFixture(t, fastParams(), 2, 0)
	f.cycle(100, 100)
	before := f.cycle(100, lost)
	for range 5 {
		f.e.RecordInvalid(f.addrs[1], f.now)
	}
	d := f.e.Tick(f.now)
	b, a := before.Record.Endpoints[1], d.Record.Endpoints[1]
	if a.Invalid != 5 || a.Samples != b.Samples || a.Loss != b.Loss || a.TrailingLosses != 1 {
		t.Errorf("invalid samples changed stats: before %+v after %+v", b, a)
	}
	f.e.Record(netip.MustParseAddrPort("198.51.100.1:1"), stats.Sample{At: f.now})
	f.e.RecordInvalid(netip.MustParseAddrPort("198.51.100.1:1"), f.now)
}

// TestAccumulatorFlicker: one flicker (a fast probe on the active) or one
// expected loss (on the target) costs only its own duration; the
// accumulator drains while the condition is false and never restarts.
func TestAccumulatorFlicker(t *testing.T) {
	p := fastParams()
	p.LossWeight = 1
	f := newFixture(t, p, 2, 0)
	f.cycle(100, 100)
	f.cycle(100, 100)
	// #0 at 120 vs #1 at 100: G = 1.2 ≥ 1.15.
	f.cycle(120, 100)
	f.cycle(120, 100)
	d := f.cycle(120, 100)
	acc := rule(d, RuleDegrade, netip.AddrPort{})
	if acc.Value != 6*time.Second || !acc.Active {
		t.Fatalf("degrade accumulator %v active=%v, want 6s", acc.Value, acc.Active)
	}
	// One expected loss on the target: p̂ jumps, G < 1.15 for one slot pair.
	f.probe(0, 120)
	d = f.probe(1, lost)
	if r := rule(d, RuleDegrade, netip.AddrPort{}); r.Active || r.Value != 6*time.Second {
		t.Fatalf("after loss: %+v, want inactive at 6s", r)
	}
	d = f.probe(0, 120)
	if r := rule(d, RuleDegrade, netip.AddrPort{}); r.Active || r.Value != 5*time.Second {
		t.Fatalf("draining: %+v, want 5s", r)
	}
	d = f.probe(1, 100)
	if r := rule(d, RuleDegrade, netip.AddrPort{}); !r.Active || r.Value != 6*time.Second {
		t.Fatalf("recovered: %+v, want 6s", r)
	}
	// One flicker on the active: a single fast probe.
	d = f.probe(0, 100)
	if r := rule(d, RuleDegrade, netip.AddrPort{}); r.Active || r.Value != 5*time.Second {
		t.Fatalf("flicker: %+v, want 5s", r)
	}
	f.probe(1, 100) // 4s
	f.probe(0, 120) // 5s
	for range 4 {
		d = f.cycle(120, 100)
		if d.Switch {
			break
		}
	}
	wantSwitch(t, d, KindDegrade, f.addrs[1])
	if r := rule(d, RuleDegrade, netip.AddrPort{}); r.Value != p.Persist {
		t.Errorf("fired at %v, want %v", r.Value, p.Persist)
	}
	// Total: 6 + (−1 +1) + (−1 −1 +1) + 5 more seconds; the switch is 4 s
	// later than without flickers, not a full persist later.
	f.commit(d)
	if r := rule(f.probe(0, 120), RuleDegrade, netip.AddrPort{}); r.Value != 0 {
		t.Errorf("accumulator not reset by switch: %v", r.Value)
	}
}

// TestFreshnessOnlyAtSwitchTime: a stale target delays the switch and keeps
// the accumulator; the switch happens at the target's next reply.
func TestFreshnessOnlyAtSwitchTime(t *testing.T) {
	f := newFixture(t, fastParams(), 2, 0)
	f.cycle(100, 100)
	f.cycle(100, 100)
	var d Decision
	for range 4 {
		d = f.cycle(200, 100)
	}
	if r := rule(d, RuleDegrade, netip.AddrPort{}); r.Value != 8*time.Second {
		t.Fatalf("degrade %v, want 8s", r.Value)
	}
	// 8 s accumulated; #1's next probes are lost (loss weight 0: still better).
	d = f.cycle(200, lost) // 10 s: fired, target stale
	wantBlocked(t, d, BlockerNotFresh, "target not fresh")
	if r := rule(d, RuleDegrade, netip.AddrPort{}); r.Value != 10*time.Second || !r.Fired {
		t.Fatalf("degrade %+v, want fired at 10s", r)
	}
	for range 3 {
		d = f.cycle(200, lost)
		wantBlocked(t, d, BlockerNotFresh, "target not fresh")
		if r := rule(d, RuleDegrade, netip.AddrPort{}); r.Value != 10*time.Second {
			t.Fatalf("stale target reset the accumulator: %v", r.Value)
		}
	}
	f.probe(0, 200)
	d = f.probe(1, 100)
	wantSwitch(t, d, KindDegrade, f.addrs[1])
}

// TestNoCommitRetries: a proposed switch that is not committed (nft commit
// failed) is proposed again on the next tick with the accumulator intact.
func TestNoCommitRetries(t *testing.T) {
	f := newFixture(t, fastParams(), 2, 0)
	f.cycle(100, 100)
	var d Decision
	for !d.Switch {
		d = f.cycle(200, 100)
	}
	wantSwitch(t, d, KindDegrade, f.addrs[1])
	d = f.probe(0, 200)
	wantSwitch(t, d, KindDegrade, f.addrs[1])
	if f.e.Selected() != f.addrs[0] {
		t.Fatal("selection changed without Commit")
	}
	f.commit(d)
	if f.e.Selected() != f.addrs[1] {
		t.Fatal("Commit did not change the selection")
	}
}

func TestGatedComparison(t *testing.T) {
	p := DefaultParams()
	// Precise latency shift (S8): latency passes the gate.
	d := steadyGate(p, calibCases[9])
	g := d.Record.Endpoints[1].Gate
	if g.RLatGated <= 0 || g.RLatGated >= g.RLat || g.RLossGated != 0 || float64(g.G) < 1+p.Margin {
		t.Errorf("S8 gate %+v", *g)
	}
	// In-noise loss difference (6% vs 3%): the loss component is gated to
	// zero although the point estimates differ.
	d = steadyGate(p, calibCase{paths: func() []path { return []path{steady(150, 0.06), steady(180, 0.03)} }})
	g = d.Record.Endpoints[1].Gate
	if g.RLoss <= 0 || g.RLossGated != 0 {
		t.Errorf("6%% vs 3%% loss not gated: %+v", *g)
	}
	// Separate gating: the combined test would hide the latency shift.
	ab := d.Record.Endpoints
	if ab[0].Gate != nil {
		t.Error("active has a gate")
	}
	// G uses the bias ratio (1+β·i_A)/(1+β·i_B).
	if want := 1 / (1 + p.OrderBias); math.Abs(float64(g.Bias)-want) > 1e-12 {
		t.Errorf("bias %v, want %v", g.Bias, want)
	}
	if want := math.Exp(float64(g.RLatGated+g.RLossGated)) * float64(g.Bias); math.Abs(float64(g.G)-want) > 1e-12 {
		t.Errorf("G %v, want %v", g.G, want)
	}
}

func TestCooldownAllKinds(t *testing.T) {
	p := fastParams()
	p.Cooldown = 30 * time.Second

	t.Run("degrade from start", func(t *testing.T) {
		f := newFixture(t, p, 2, 0)
		f.cycle(100, 100)
		var d Decision
		for !d.Switch {
			d = f.cycle(200, 100)
			if !d.Switch && rule(d, RuleDegrade, netip.AddrPort{}).Fired {
				wantBlocked(t, d, BlockerCooldown, "cooldown ")
			}
		}
		if got := f.now.Sub(t0); got != p.Cooldown {
			t.Errorf("switch at %v, want %v", got, p.Cooldown)
		}
	})
	t.Run("outage from start", func(t *testing.T) {
		f := newFixture(t, p, 2, 0)
		f.cycle(100, 100)
		f.cycle(100, 100)
		var d Decision
		for !d.Switch {
			d = f.cycle(lost, 100)
		}
		wantSwitch(t, d, KindOutage, f.addrs[1])
		if got := f.now.Sub(t0); got != p.Cooldown {
			t.Errorf("switch at %v, want %v", got, p.Cooldown)
		}
	})
	t.Run("restore from start", func(t *testing.T) {
		q := p
		q.Cooldown = 60 * time.Second
		f := newFixture(t, q, 2, 1)
		var d Decision
		for !d.Switch {
			d = f.cycle(100, 100)
			if r := rule(d, RuleRestore, f.addrs[0]); r.Fired && !d.Switch {
				wantBlocked(t, d, BlockerCooldown, "cooldown ")
			}
		}
		wantSwitch(t, d, KindRestore, f.addrs[0])
		if got := f.now.Sub(t0); got != q.Cooldown {
			t.Errorf("switch at %v, want %v", got, q.Cooldown)
		}
	})
	t.Run("startup from start", func(t *testing.T) {
		f := newFixture(t, p, 2, -1)
		var d Decision
		for !d.Switch {
			d = f.cycle(100, 100)
		}
		wantSwitch(t, d, KindStartup, f.addrs[0])
		if got := f.now.Sub(t0); got != p.Cooldown {
			t.Errorf("switch at %v, want %v", got, p.Cooldown)
		}
	})
	t.Run("from last switch", func(t *testing.T) {
		f := newFixture(t, p, 2, 0)
		for f.now.Sub(t0) < p.Cooldown {
			f.cycle(100, 100)
		}
		var d Decision
		for !d.Switch {
			d = f.cycle(lost, 100)
		}
		wantSwitch(t, d, KindOutage, f.addrs[1])
		f.commit(d)
		at := f.now
		// Now #1 dies and #0 recovers: outage fires again, but waits for the
		// cooldown since the last switch.
		for d = (Decision{}); !d.Switch; {
			d = f.cycle(100, lost)
			if !d.Switch && rule(d, RuleOutage, netip.AddrPort{}).Fired {
				wantBlocked(t, d, BlockerCooldown, "cooldown ")
			}
		}
		wantSwitch(t, d, KindOutage, f.addrs[0])
		if got := f.now.Sub(at); got < p.Cooldown || got > p.Cooldown+2*time.Second {
			t.Errorf("second switch %v after the first, want the cooldown %v", got, p.Cooldown)
		}
	})
	t.Run("reload exempt", func(t *testing.T) {
		f := newFixture(t, p, 3, 0)
		f.cycle(100, 100, 100)
		f.cycle(100, 100, 100)
		if err := f.e.Reload(f.addrs[1:], f.now); err != nil {
			t.Fatal(err)
		}
		d := f.e.Tick(f.now)
		wantSwitch(t, d, KindReload, f.addrs[1])
		if d.Record.CooldownLeft == 0 {
			t.Error("test should run inside the cooldown")
		}
	})
}

func TestAdaptiveOutageK(t *testing.T) {
	for _, c := range []struct {
		loss float64
		k    int
	}{{0.05, 4}, {0.10, 5}, {0, OutageMinK}, {0.5, OutageMaxK}} {
		p := DefaultParams()
		p.Cooldown = 0
		s := newSim(p, 1, []path{steady(150, c.loss), steady(150, 0)}, 0)
		for s.slot < 2*p.History {
			i := s.slot % 2
			ok, rtt := s.paths[i](nil, 0)
			s.eng.Record(s.addrs[i], stats.Sample{At: simEpoch.Add(s.now()), Replied: ok, RTT: rtt})
			s.slot++
		}
		// End on a reply so the run starts at 0.
		s.eng.Record(s.addrs[0], stats.Sample{At: simEpoch.Add(s.now()), Replied: true, RTT: 150 * time.Millisecond})
		s.eng.Tick(simEpoch.Add(s.now()))
		s.paths[0] = gaussian(0, 0, 1)
		var d Decision
		for run := 1; run <= OutageMaxK; run++ {
			s.stepSlot() // #0: lost
			d = s.last
			r := rule(d, RuleOutage, netip.AddrPort{})
			if r.K != c.k || r.Run != run {
				t.Fatalf("loss %.2f run %d: K=%d run=%d, want K=%d (base excludes the trailing run)", c.loss, run, r.K, r.Run, c.k)
			}
			if d.Switch != (run >= c.k) {
				t.Fatalf("loss %.2f run %d: switch=%v (%s)", c.loss, run, d.Switch, d.Reason)
			}
			if d.Switch {
				wantSwitch(t, d, KindOutage, s.addrs[1])
				break
			}
			s.stepSlot() // #1
		}
	}
}

func TestRevertTieAndBackoff(t *testing.T) {
	p := fastParams()
	// The bias keeps G(#1→#0) clearly ≥ 1 while the residual weight of old
	// slow samples of #0 decays.
	p.OrderBias = 0.02
	f := newFixture(t, p, 2, 1)
	// Equal endpoints: G(#1→#0) = 1.02 ≥ 1 → revert after WTR.
	var d Decision
	for !d.Switch {
		d = f.cycle(100, 100)
		if !d.Switch && f.now.Sub(t0) > 3*time.Second {
			wantBlocked(t, d, BlockerRestoreHold, "restore hold ")
		}
	}
	wantSwitch(t, d, KindRestore, f.addrs[0])
	if r := rule(d, RuleRestore, f.addrs[0]); r.Value != p.WaitToRestore || r.Level != 0 {
		t.Errorf("restore %+v", r)
	}
	f.commit(d)

	// Each degradation exit from #0 raises its level: hold 2×, 4×, 8×, 8×.
	for _, level := range []int{1, 2, 3, 3} {
		for d = (Decision{}); !d.Switch; {
			d = f.cycle(200, 100)
		}
		wantSwitch(t, d, KindDegrade, f.addrs[1])
		f.commit(d)
		var start time.Time
		d = Decision{}
		for i := 0; !d.Switch; i++ {
			d = f.probe(i%2, 100)
			if start.IsZero() && rule(d, RuleRestore, f.addrs[0]).Active {
				start = f.now
			}
		}
		wantSwitch(t, d, KindRestore, f.addrs[0])
		r := rule(d, RuleRestore, f.addrs[0])
		hold := p.WaitToRestore << level
		if r.Level != level || r.Hold != hold {
			t.Fatalf("level %d hold %v, want %d %v", r.Level, r.Hold, level, hold)
		}
		// The first active tick already counts one interval.
		if got := f.now.Sub(start) + p.Interval; got != hold {
			t.Errorf("restore after %v of net time, want %v", got, hold)
		}
		f.commit(d)
	}
	// One level less per hour without a degradation exit.
	for range int(RestoreLevelDecay/time.Second) / 2 {
		d = f.cycle(100, 100)
	}
	if lv := d.Record.Endpoints[0].RestoreLevel; lv != 2 {
		t.Errorf("level after an hour: %d, want 2", lv)
	}
	for range 2 * int(RestoreLevelDecay/time.Second) / 2 {
		d = f.cycle(100, 100)
	}
	if lv := d.Record.Endpoints[0].RestoreLevel; lv != 0 {
		t.Errorf("level after three hours: %d, want 0", lv)
	}
}

func TestTiesGoToEarlier(t *testing.T) {
	p := fastParams()
	t.Run("restore", func(t *testing.T) {
		f := newFixture(t, p, 3, 2)
		var d Decision
		for !d.Switch {
			d = f.cycle(100, 100, 100)
		}
		// #0 and #1 fire on the same tick with identical cost.
		if !rule(d, RuleRestore, f.addrs[1]).Fired {
			t.Fatal("#1 should have fired too")
		}
		wantSwitch(t, d, KindRestore, f.addrs[0])
	})
	t.Run("startup", func(t *testing.T) {
		f := newFixture(t, p, 3, -1)
		d := f.cycle(100, 100, 100)
		d = f.cycle(100, 100, 100)
		wantSwitch(t, d, KindStartup, f.addrs[0])
	})
	t.Run("degrade", func(t *testing.T) {
		f := newFixture(t, p, 3, 0)
		var d Decision
		for !d.Switch {
			d = f.cycle(200, 100, 100)
		}
		wantSwitch(t, d, KindDegrade, f.addrs[1])
	})
	t.Run("order bias breaks near-ties", func(t *testing.T) {
		q := p
		q.OrderBias = 0.02
		f := newFixture(t, q, 2, 0)
		var d Decision
		for range 20 {
			d = f.cycle(100, 100)
		}
		wantBlocked(t, d, BlockerNothingBetter, "nothing better beyond noise")
		if g := d.Record.Endpoints[1].Gate.G; math.Abs(float64(g)-1/1.02) > 1e-12 {
			t.Errorf("G(#0→#1) = %v, want 1/1.02", g)
		}
	})
}

func TestAllDownNoSwitch(t *testing.T) {
	f := newFixture(t, fastParams(), 3, 0)
	f.cycle(100, 100, 100)
	f.cycle(100, 100, 100)
	for range 50 {
		d := f.cycle(lost, lost, lost)
		if d.Switch {
			t.Fatalf("switched with all endpoints down: %s", d.Reason)
		}
		wantBlocked(t, d, BlockerAllDown, "all down")
	}
}

// TestOutageAfterAllDownRecovery: losses while every path was down
// (common-mode) do not count toward the outage run, so recovering at once
// causes no outage switch, whichever endpoint the round-robin probes first
// after the recovery and even if the active's first probe after it is lost.
// Losses after the recovery count from zero: a genuine outage starting then
// still switches at its K-th loss.
func TestOutageAfterAllDownRecovery(t *testing.T) {
	const n, active = 4, 1
	for phase := range n {
		for _, activeLosses := range []int{0, 1, 2, -1} { // -1: until switch
			name := fmt.Sprintf("first probe after recovery #%d, active then loses %d", phase, activeLosses)
			if activeLosses < 0 {
				name = fmt.Sprintf("first probe after recovery #%d, active stays down", phase)
			}
			t.Run(name, func(t *testing.T) {
				p := fastParams()
				p.WaitToRestore = 0
				// Keep pre-outage replies in the window: an all-loss window
				// has infinite cost and legitimately triggers rule 2.
				p.History = 64
				f := newFixture(t, p, n, active)
				f.cycle(100, 100, 100, 100)
				f.cycle(100, 100, 100, 100)
				slot := 0
				// All down for 8 cycles.
				for ; slot < 8*n || slot%n != phase; slot++ {
					d := f.probe(slot%n, lost)
					if d.Switch {
						t.Fatalf("switched while all down: %s", d.Reason)
					}
					if r := rule(d, RuleOutage, netip.AddrPort{}); r.Run >= r.K {
						t.Fatalf("slot %d: common-mode losses counted: run %d ≥ K %d", slot, r.Run, r.K)
					}
				}
				// Simultaneous recovery of every path but, for activeLosses
				// probes, the active.
				lostActive, k := 0, 0
				for end := slot + 12*n; slot < end; slot++ {
					i := slot % n
					rtt := 100.0
					if i == active && (activeLosses < 0 || lostActive < activeLosses) {
						rtt = lost
						lostActive++
					}
					d := f.probe(i, rtt)
					r := rule(d, RuleOutage, netip.AddrPort{})
					k = r.K
					if d.Blocker == BlockerOutageUnconfirmed {
						t.Fatalf("slot %d: unexpected %s", slot, d.Reason)
					}
					if activeLosses < 0 && r.Run >= r.K {
						// A loss of the active probed first after the recovery
						// is still common-mode (nothing is fresh yet).
						if want := r.K + btoi(phase == active); lostActive != want {
							t.Fatalf("run reached K=%d after %d post-recovery losses, want %d", r.K, lostActive, want)
						}
						wantSwitch(t, d, KindOutage, f.addrs[0])
						return
					}
					if d.Switch {
						t.Fatalf("spurious %s switch after recovery (slot %d): %s", d.Kind, slot, d.Reason)
					}
				}
				if activeLosses < 0 {
					t.Fatalf("no outage switch after %d post-recovery losses (K=%d)", lostActive, k)
				}
				if f.e.Selected() != f.addrs[active] {
					t.Errorf("selection %v, want %v", f.e.Selected(), f.addrs[active])
				}
			})
		}
	}
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// correlatedOutage: #0 (active) and #1 fail together while #2 (slower)
// stays up, so the outage is not common-mode. A cooldown holds the switch
// until #1 has recovered: at the tick after #1's first reply the cooldown
// ends and #1 is the cheapest fresh target, but #0's last loss predates
// #1's replies. It returns that tick's decision.
func correlatedOutage(t *testing.T) *fixture {
	p := fastParams()
	p.Cooldown = 32 * time.Second
	f := newFixture(t, p, 3, 0)
	f.cycle(100, 100, 100) // slots 0-2
	f.cycle(100, 100, 300) // slots 3-5
	for range 8 {          // slots 6-29
		f.cycle(lost, lost, 300)
	}
	f.probe(0, lost) // slot 30
	return f
}

// TestOutageWaitKeepsState: an outage whose newest loss predates the
// target's replies waits (keeping the run), and the active's next loss
// switches at once.
func TestOutageWaitKeepsState(t *testing.T) {
	f := correlatedOutage(t)
	d := f.probe(1, 100) // slot 31: #1 replies again; cooldown ends at this tick
	if d.Record.CooldownLeft != 0 {
		t.Fatalf("cooldown %v left", d.Record.CooldownLeft)
	}
	wantBlocked(t, d, BlockerOutageUnconfirmed, "outage run predates target's replies: #0 ")
	if !strings.HasSuffix(d.Reason, "waiting for the active's next probe") {
		t.Errorf("reason %q", d.Reason)
	}
	d = f.probe(2, 300)
	wantBlocked(t, d, BlockerOutageUnconfirmed, "outage run predates target's replies")
	d = f.probe(0, lost)
	wantSwitch(t, d, KindOutage, f.addrs[1])
}

// TestOutageGenuineSwitchesAtKthLoss: in round-robin the target's last
// reply precedes the active's K-th loss, so a real outage still switches on
// the tick right after the K-th loss, for every position of the active.
func TestOutageGenuineSwitchesAtKthLoss(t *testing.T) {
	const n = 4
	for active := range n {
		t.Run(fmt.Sprintf("active #%d", active), func(t *testing.T) {
			p := fastParams()
			p.WaitToRestore = 0
			f := newFixture(t, p, n, active)
			for range 3 {
				f.cycle(100, 100, 100, 100)
			}
			for slot := 0; ; slot++ {
				i := slot % n
				rtt := 100.0
				if i == active {
					rtt = lost
				}
				d := f.probe(i, rtt)
				r := rule(d, RuleOutage, netip.AddrPort{})
				if d.Blocker == BlockerOutageUnconfirmed {
					t.Fatalf("genuine outage reported unconfirmed: %s", d.Reason)
				}
				if r.Run >= r.K {
					if i != active {
						t.Fatalf("run reached K on a non-active slot")
					}
					// Equal costs: the tie goes to the earliest other endpoint.
					want := 0
					if active == 0 {
						want = 1
					}
					wantSwitch(t, d, KindOutage, f.addrs[want])
					if !strings.HasPrefix(d.Reason, "outage: ") {
						t.Errorf("reason %q", d.Reason)
					}
					return
				}
				if d.Switch {
					t.Fatalf("switched before K: %s", d.Reason)
				}
				if slot > 20*n {
					t.Fatal("no outage")
				}
			}
		})
	}
}

func TestUnlistedStart(t *testing.T) {
	p := fastParams()
	p.MinSamples = 4
	f := newFixture(t, p, 3, -1)
	if f.e.Selected().IsValid() {
		t.Fatal("selection without a listed endpoint")
	}
	for range 3 {
		d := f.cycle(150, 120, 130)
		wantBlocked(t, d, BlockerWarmingUp, "warming up")
	}
	// The first eligible endpoint (#0 after its 4th sample) is the only
	// candidate at that tick.
	d := f.probe(0, 150)
	wantSwitch(t, d, KindStartup, f.addrs[0])
	if d.From.IsValid() {
		t.Errorf("From = %v, want none", d.From)
	}
	f.commit(d)
	if f.e.Selected() != f.addrs[0] {
		t.Fatal("not selected")
	}
}

func TestReload(t *testing.T) {
	p := fastParams()
	p.Cooldown = time.Hour
	p.OrderBias = 0.02
	f := newFixture(t, p, 3, 1) // a b c, selected b
	for range 3 {
		f.cycle(100, 110, 120)
	}
	d := f.e.Tick(f.now)
	samplesA := d.Record.Endpoints[0].Samples

	t.Run("keep selection", func(t *testing.T) {
		list := []netip.AddrPort{f.addrs[2], f.addrs[1], f.addrs[0]}
		if err := f.e.Reload(list, f.now); err != nil {
			t.Fatal(err)
		}
		d := f.e.Tick(f.now)
		if d.Switch || f.e.Selected() != f.addrs[1] {
			t.Fatalf("switched on a reload keeping the selection: %s", d.Reason)
		}
		// Bias follows the new order: c is now #0.
		c := d.Record.Endpoints[0]
		if c.Addr != f.addrs[2] || c.Index != 0 || c.BiasedCost != c.Cost {
			t.Errorf("reordered view %+v", c)
		}
		if a := d.Record.Endpoints[2]; a.Addr != f.addrs[0] || a.Samples != samplesA || a.BiasedCost != a.Cost*1.04 {
			t.Errorf("a lost its history or bias: %+v", a)
		}
	})
	t.Run("remove selection", func(t *testing.T) {
		d := netip.MustParseAddrPort("[2001:db8::1]:51820")
		list := []netip.AddrPort{f.addrs[2], f.addrs[0], d}
		if err := f.e.Reload(list, f.now); err != nil {
			t.Fatal(err)
		}
		if f.e.Selected().IsValid() {
			t.Fatal("removed selection still selected")
		}
		dec := f.e.Tick(f.now)
		// Best eligible-or-fresh by biased cost: a (100·1.02) vs c (120).
		wantSwitch(t, dec, KindReload, f.addrs[0])
		if dec.From != f.addrs[1] || dec.Record.Removed != f.addrs[1] || dec.Record.CooldownLeft == 0 {
			t.Errorf("reload decision From=%v Removed=%v cooldown=%v", dec.From, dec.Record.Removed, dec.Record.CooldownLeft)
		}
		if nd := dec.Record.Endpoints[2]; nd.Addr != d || nd.Samples != 0 || nd.Eligible {
			t.Errorf("new endpoint not empty: %+v", nd)
		}
		if len(dec.Record.Endpoints) != 3 {
			t.Errorf("removed endpoint still listed")
		}
		f.e.Commit(dec, f.now)
		if f.e.Selected() != f.addrs[0] {
			t.Fatal("reload switch not committed")
		}
		if f.e.Tick(f.now).Record.Removed.IsValid() {
			t.Error("removed endpoint kept after the switch")
		}
	})
	t.Run("errors keep state", func(t *testing.T) {
		before := f.e.List()
		if err := f.e.Reload(nil, f.now); err == nil {
			t.Error("empty list accepted")
		}
		if err := f.e.Reload([]netip.AddrPort{f.addrs[0], f.addrs[0]}, f.now); err == nil {
			t.Error("duplicate accepted")
		}
		if got := f.e.List(); len(got) != len(before) || got[0] != before[0] {
			t.Errorf("list changed: %v", got)
		}
	})
	t.Run("removed endpoint returns empty", func(t *testing.T) {
		if err := f.e.Reload(f.addrs, f.now); err != nil {
			t.Fatal(err)
		}
		if v := f.e.Tick(f.now).Record.Endpoints[1]; v.Samples != 0 || v.RestoreLevel != 0 {
			t.Errorf("re-added endpoint kept history: %+v", v)
		}
	})
}

func TestTimeGapReset(t *testing.T) {
	f := newFixture(t, fastParams(), 2, 0)
	f.cycle(100, 100)
	f.cycle(200, 100)
	d := f.cycle(200, 100)
	if r := rule(d, RuleDegrade, netip.AddrPort{}); r.Value == 0 {
		t.Fatal("no accumulation")
	}
	f.probe(0, lost)
	d = f.probe(0, lost)
	if d.Record.Endpoints[0].TrailingLosses != 2 {
		t.Fatalf("run %d", d.Record.Endpoints[0].TrailingLosses)
	}
	// Suspend: the next tick comes 11 intervals later.
	f.now = f.now.Add(11 * time.Second)
	d = f.e.Tick(f.now)
	if !d.Record.Gap {
		t.Fatal("gap not detected")
	}
	if r := rule(d, RuleDegrade, netip.AddrPort{}); r.Value != 0 {
		t.Errorf("accumulator %v after gap, want 0", r.Value)
	}
	if v := d.Record.Endpoints[0]; v.TrailingLosses != 0 {
		t.Errorf("loss run %d after gap, want 0", v.TrailingLosses)
	}
	// A clock step backwards is a discontinuity too.
	f.now = f.now.Add(-time.Minute)
	if d = f.e.Tick(f.now); !d.Record.Gap {
		t.Error("backwards step not treated as gap")
	}
	// Exactly 10 intervals is not a gap.
	f.now = f.now.Add(10 * time.Second)
	if d = f.e.Tick(f.now); d.Record.Gap {
		t.Error("10 intervals treated as gap")
	}
}

func TestSingleEndpointNeverSwitches(t *testing.T) {
	f := newFixture(t, fastParams(), 1, 0)
	d := f.probe(0, 100)
	d = f.probe(0, 100)
	wantBlocked(t, d, BlockerNoCandidate, "no other eligible candidate")
	for range 20 {
		if d = f.probe(0, lost); d.Switch {
			t.Fatal("switched to the active endpoint")
		}
	}
	wantBlocked(t, d, BlockerAllDown, "all down")
}

func TestDecisionJSON(t *testing.T) {
	f := newFixture(t, fastParams(), 2, 0)
	f.cycle(100, lost)
	d := f.cycle(100, lost) // #1 has no replies: infinite cost
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`"latency":"+Inf"`, `"cost":"+Inf"`, `"g":0`, `"r_lat":"-Inf"`, `"addr":"192.0.2.10:51820"`, `"blocker":"`} {
		if !strings.Contains(s, want) {
			t.Errorf("JSON lacks %s: %s", want, s)
		}
	}
	var back Decision
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if !math.IsInf(float64(back.Record.Endpoints[1].Cost), 1) || back.Record.Endpoints[0].Addr != f.addrs[0] {
		t.Errorf("round trip: %+v", back.Record.Endpoints)
	}
	var x Float
	if err := json.Unmarshal([]byte(`"NaN"`), &x); err != nil || !math.IsNaN(float64(x)) {
		t.Errorf("NaN: %v %v", x, err)
	}
	if err := json.Unmarshal([]byte(`"bogus"`), &x); err == nil {
		t.Error("bogus accepted")
	}
}

// TestBlockerReasons: the "no switch because …" reason names the guard that
// actually blocks, for every guard type.
func TestBlockerReasons(t *testing.T) {
	p := fastParams()
	cases := []struct {
		name    string
		blocker Blocker
		prefix  string
		run     func(t *testing.T) Decision
	}{
		{"warming-up", BlockerWarmingUp, "warming up: active #0", func(t *testing.T) Decision {
			f := newFixture(t, p, 2, 0)
			return f.probe(0, 100)
		}},
		{"cooldown", BlockerCooldown, "cooldown 12s left (degrade to #1", func(t *testing.T) Decision {
			q := p
			q.Cooldown = 30 * time.Second
			q.Persist = 4 * time.Second
			f := newFixture(t, q, 2, 0)
			f.cycle(100, 100)
			var d Decision
			for f.now.Sub(t0) < 18*time.Second {
				d = f.cycle(200, 100)
			}
			return d
		}},
		{"persist", BlockerPersist, "persist 2/10 s (#1 ", func(t *testing.T) Decision {
			f := newFixture(t, p, 2, 0)
			f.cycle(100, 100)
			f.cycle(200, 100)
			return f.probe(0, 200)
		}},
		{"restore-hold", BlockerRestoreHold, "restore hold 3/20 s for #0 ", func(t *testing.T) Decision {
			f := newFixture(t, p, 2, 1)
			f.cycle(100, 100)
			f.cycle(100, 100)
			return f.cycle(100, 100)
		}},
		{"not-fresh", BlockerNotFresh, "target not fresh: #1 ", func(t *testing.T) Decision {
			f := newFixture(t, p, 2, 0)
			f.cycle(100, 100)
			f.cycle(100, 100)
			for range 4 {
				f.cycle(200, 100)
			}
			return f.cycle(200, lost)
		}},
		{"nothing-better", BlockerNothingBetter, "nothing better beyond noise", func(t *testing.T) Decision {
			f := newFixture(t, p, 2, 0)
			f.cycle(100, 100)
			return f.cycle(100, 105)
		}},
		{"all-down", BlockerAllDown, "all down", func(t *testing.T) Decision {
			f := newFixture(t, p, 2, 0)
			f.cycle(100, 100)
			f.cycle(100, 100)
			return f.cycle(lost, lost)
		}},
		{"no-candidate", BlockerNoCandidate, "no other eligible candidate", func(t *testing.T) Decision {
			f := newFixture(t, p, 2, 0)
			f.cycle(100, lost)
			return f.cycle(100, lost)
		}},
		{"startup warming", BlockerWarmingUp, "warming up: no listed selection", func(t *testing.T) Decision {
			f := newFixture(t, p, 2, -1)
			return f.cycle(100, 100)
		}},
		{"outage-unconfirmed", BlockerOutageUnconfirmed, "outage run predates target's replies: #0 ", func(t *testing.T) Decision {
			return correlatedOutage(t).probe(1, 100)
		}},
		{"outage cooldown", BlockerCooldown, "cooldown ", func(t *testing.T) Decision {
			q := p
			q.Cooldown = time.Minute
			f := newFixture(t, q, 2, 0)
			f.cycle(100, 100)
			var d Decision
			for range 4 {
				d = f.cycle(lost, 100)
			}
			if !rule(d, RuleOutage, netip.AddrPort{}).Fired {
				t.Fatal("outage did not fire")
			}
			return d
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := c.run(t)
			wantBlocked(t, d, c.blocker, c.prefix)
		})
	}
}
