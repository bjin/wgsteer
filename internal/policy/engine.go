package policy

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"time"

	"github.com/bjin/wgsteer/internal/endpoints"
	"github.com/bjin/wgsteer/internal/stats"
)

// endpointState is everything the engine keeps per listed endpoint. It
// survives a list reload while the endpoint stays listed.
type endpointState struct {
	addr        netip.AddrPort
	index       int
	name        string // configured name, empty when unnamed
	ring        *stats.Ring
	invalid     int
	lastInvalid time.Time
	// run is the trailing loss run counted for the outage rule. Unlike
	// ring.TrailingLosses it restarts on a time discontinuity and on every
	// tick where no endpoint is fresh: losses during a common-mode outage
	// (local uplink or server down) are no evidence against one endpoint.
	run      int
	est      stats.Estimate
	estValid bool
	// restoreAcc is the revert accumulator (meaningful only while the
	// endpoint is listed before the active one).
	restoreAcc time.Duration
	level      int
	levelAt    time.Time
}

func (s *endpointState) estimate(sp stats.Params) stats.Estimate {
	if !s.estValid {
		s.est = sp.Estimate(s.ring, 0)
		s.estValid = true
	}
	return s.est
}

// Engine is the decision state machine. It is not safe for concurrent use;
// the daemon's event loop owns it.
type Engine struct {
	p        Params
	sp       stats.Params
	list     []*endpointState
	byAddr   map[netip.AddrPort]*endpointState
	selected *endpointState
	// removed is a selection dropped by Reload; rule 6 switches away from
	// it immediately.
	removed    netip.AddrPort
	lastSwitch time.Time
	lastTick   time.Time
	degradeAcc time.Duration
}

// New creates an engine for list. selected is the live device's endpoint if
// it is listed, or the zero value when the device is on an unlisted
// endpoint (rule 5 then switches to the best candidate once one is
// eligible). now is the daemon start; the cooldown also runs from it. Names
// label the endpoints in reasons and views.
func New(p Params, list []endpoints.Endpoint, selected netip.AddrPort, now time.Time) (*Engine, error) {
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("policy parameters: %w", err)
	}
	norm, err := normalizeList(list)
	if err != nil {
		return nil, err
	}
	e := &Engine{
		p: p,
		sp: stats.Params{
			HalfLife:     p.HalfLife,
			PriorMean:    stats.DefaultPriorMean,
			PriorWeight:  stats.DefaultPriorWeight,
			JitterWeight: p.JitterWeight,
		},
		byAddr:     make(map[netip.AddrPort]*endpointState, len(norm)),
		lastSwitch: now,
		lastTick:   now,
	}
	for i, ep := range norm {
		s := &endpointState{addr: ep.Addr, index: i, name: ep.Name, ring: stats.NewRing(p.History)}
		e.list = append(e.list, s)
		e.byAddr[ep.Addr] = s
	}
	if selected.IsValid() {
		s := e.byAddr[endpoints.Normalize(selected)]
		if s == nil {
			return nil, fmt.Errorf("selected endpoint %v is not listed", selected)
		}
		e.selected = s
	}
	return e, nil
}

func normalizeList(list []endpoints.Endpoint) ([]endpoints.Endpoint, error) {
	if len(list) == 0 {
		return nil, errors.New("endpoint list is empty")
	}
	out := make([]endpoints.Endpoint, len(list))
	seen := make(map[netip.AddrPort]bool, len(list))
	for i, ep := range list {
		n := endpoints.Normalize(ep.Addr)
		if !n.IsValid() {
			return nil, fmt.Errorf("endpoint %s is invalid", endpoints.Label(ep.Name, i))
		}
		if seen[n] {
			return nil, fmt.Errorf("duplicate endpoint %v", n)
		}
		seen[n] = true
		out[i] = endpoints.Endpoint{Addr: n, Name: ep.Name}
	}
	return out, nil
}

// Params returns the engine's parameters.
func (e *Engine) Params() Params { return e.p }

// Selected returns the selected endpoint, or the zero value if none (the
// device is on an unlisted endpoint, or a reload removed the selection).
func (e *Engine) Selected() netip.AddrPort {
	if e.selected == nil {
		return netip.AddrPort{}
	}
	return e.selected.addr
}

// List returns the current endpoint list in preference order.
func (e *Engine) List() []netip.AddrPort {
	out := make([]netip.AddrPort, len(e.list))
	for i, s := range e.list {
		out[i] = s.addr
	}
	return out
}

// Record stores a valid sample for ep. Samples for unlisted endpoints (e.g.
// a slot that straddled a reload) are ignored.
func (e *Engine) Record(ep netip.AddrPort, s stats.Sample) {
	st := e.byAddr[endpoints.Normalize(ep)]
	if st == nil {
		return
	}
	st.ring.Add(s)
	st.estValid = false
	if s.Replied {
		st.run = 0
	} else {
		st.run++
	}
}

// RecordInvalid counts a probe sent without a usable session. It is excluded
// from all statistics and does not break or extend loss runs.
func (e *Engine) RecordInvalid(ep netip.AddrPort, at time.Time) {
	st := e.byAddr[endpoints.Normalize(ep)]
	if st == nil {
		return
	}
	st.invalid++
	st.lastInvalid = at
}

// Reload replaces the endpoint list (rule 6). Endpoints still
// listed keep their history, counters, restore level and accumulators; new
// ones start empty; removed ones are dropped. Order bias and names follow
// the new list. If the selection was removed, the next Tick proposes a reload switch
// to the best eligible-or-fresh candidate, ignoring the cooldown. On error
// the engine is unchanged.
func (e *Engine) Reload(list []endpoints.Endpoint, now time.Time) error {
	norm, err := normalizeList(list)
	if err != nil {
		return err
	}
	byAddr := make(map[netip.AddrPort]*endpointState, len(norm))
	next := make([]*endpointState, len(norm))
	for i, ep := range norm {
		s := e.byAddr[ep.Addr]
		if s == nil {
			s = &endpointState{addr: ep.Addr, ring: stats.NewRing(e.p.History)}
		}
		s.index, s.name = i, ep.Name
		next[i] = s
		byAddr[ep.Addr] = s
	}
	if e.selected != nil && byAddr[e.selected.addr] == nil {
		e.removed = e.selected.addr
		e.selected = nil
	}
	e.list, e.byAddr = next, byAddr
	return nil
}

// Commit applies an executed switch (or a simulated one in dry-run):
// the selection becomes d.To, every accumulator resets, the cooldown
// restarts and, for a degradation switch, the restore level of the endpoint
// left rises. Not calling Commit after a proposed switch (e.g. the nft
// commit failed) keeps all accumulators, so a later Tick proposes it again.
func (e *Engine) Commit(d Decision, now time.Time) {
	if !d.Switch {
		return
	}
	if d.Kind == KindDegrade {
		if from := e.byAddr[endpoints.Normalize(d.From)]; from != nil {
			from.level = min(from.level+1, MaxRestoreLevel)
			from.levelAt = now
		}
	}
	e.selected = e.byAddr[endpoints.Normalize(d.To)]
	e.removed = netip.AddrPort{}
	e.lastSwitch = now
	e.resetAccumulators()
}

func (e *Engine) resetAccumulators() {
	e.degradeAcc = 0
	for _, s := range e.list {
		s.restoreAcc = 0
	}
}

func (e *Engine) hold(s *endpointState) time.Duration {
	return e.p.WaitToRestore << s.level
}

// cand is the per-tick evaluation of one endpoint.
type cand struct {
	st         *endpointState
	est        stats.Estimate
	lossFactor float64
	cost       float64
	biased     float64
	warm       bool // ≥ MinSamples valid samples
	eligible   bool
	fresh      bool
	hasGate    bool
	gate       gate
	degrade    bool // satisfies the degradation condition (rule 2)
	restore    bool // satisfies the revert condition (rule 3)
	restoreOn  bool // revert accumulator applies (earlier than the active)
}

type gate struct {
	g, rLat, sLat, rLatGated, rLoss, sLoss, rLossGated, bias float64
}

func (g gate) view() *Gated {
	return &Gated{
		G: Float(g.g), RLat: Float(g.rLat), SLat: Float(g.sLat), RLatGated: Float(g.rLatGated),
		RLoss: Float(g.rLoss), SLoss: Float(g.sLoss), RLossGated: Float(g.rLossGated), Bias: Float(g.bias),
	}
}

// lossTerm returns the loss factor F = 1 + α·p/(1−p) and SE(ln F) by the
// delta method: α·SE_p / ((1−p)²·F).
func lossTerm(alpha float64, est stats.Estimate) (f, seLn float64) {
	p := est.Loss
	f = 1 + alpha*p/(1-p)
	seLn = alpha * est.LossSE / ((1 - p) * (1 - p) * f)
	return f, seLn
}

// latencyTerm returns the latency term and SE(ln L).
func latencyTerm(est stats.Estimate) (l, seLn float64) {
	l = math.Max(est.Latency, 1e-6)
	return l, est.LatencySE / l
}

func gated(r, cs float64) float64 {
	m := math.Abs(r) - cs
	if m <= 0 {
		return 0
	}
	return math.Copysign(m, r)
}

// compare computes the gated ratio G(A→B), "how much better B is than A
// beyond noise".
func (e *Engine) compare(a, b *cand) gate {
	c := e.p.NoiseGate
	var g gate
	g.bias = (1 + e.p.OrderBias*float64(a.st.index)) / (1 + e.p.OrderBias*float64(b.st.index))

	fa, sfa := lossTerm(e.p.LossWeight, a.est)
	fb, sfb := lossTerm(e.p.LossWeight, b.est)
	g.rLoss = math.Log(fa / fb)
	g.sLoss = math.Hypot(sfa, sfb)
	g.rLossGated = gated(g.rLoss, c*g.sLoss)

	switch af, bf := a.est.Finite(), b.est.Finite(); {
	case af && bf:
		la, sla := latencyTerm(a.est)
		lb, slb := latencyTerm(b.est)
		g.rLat = math.Log(la / lb)
		g.sLat = math.Hypot(sla, slb)
		g.rLatGated = gated(g.rLat, c*g.sLat)
	case bf: // only A has no replies: B is infinitely better
		_, slb := latencyTerm(b.est)
		g.rLat, g.sLat, g.rLatGated = math.Inf(1), slb, math.Inf(1)
	case af: // only B has no replies
		_, sla := latencyTerm(a.est)
		g.rLat, g.sLat, g.rLatGated = math.Inf(-1), sla, math.Inf(-1)
	default:
		g.rLat, g.sLat, g.rLatGated = math.NaN(), math.NaN(), math.Inf(-1)
	}
	g.g = math.Exp(g.rLatGated+g.rLossGated) * g.bias
	return g
}

// outageK is the adaptive outage run length from the base loss estimate that
// excludes the ring's whole trailing loss run: both the counted run and any
// common-mode losses before it, so neither escalates K.
func (e *Engine) outageK(s *endpointState) int {
	base := s.estimate(e.sp).Loss
	if tl := s.ring.TrailingLosses(); tl > 0 {
		base = e.sp.Estimate(s.ring, tl).Loss
	}
	k := math.Ceil(math.Log(e.p.OutageEpsilon) / math.Log(base))
	if math.IsNaN(k) {
		return OutageMaxK
	}
	return int(math.Min(math.Max(k, OutageMinK), OutageMaxK))
}

// replyStreakStart returns the send time of the oldest reply in r's trailing
// run of replies (zero if the newest sample is a loss).
func replyStreakStart(r *stats.Ring) time.Time {
	var at time.Time
	for i := 0; i < r.Len() && r.At(i).Replied; i++ {
		at = r.At(i).At
	}
	return at
}

// step advances a net-time accumulator: +dt while cond holds, −dt otherwise,
// clamped to [0, limit].
func step(acc, dt time.Duration, cond bool, limit time.Duration) time.Duration {
	if cond {
		acc += dt
	} else {
		acc -= dt
	}
	return min(max(acc, 0), limit)
}

// Tick evaluates every rule at now (after each probe slot) and proposes at
// most one switch. It advances the accumulators but changes the selection
// only through Commit.
func (e *Engine) Tick(now time.Time) Decision {
	dt := now.Sub(e.lastTick)
	gap := dt < 0 || dt > GapFactor*e.p.Interval
	if gap {
		e.resetAccumulators()
		for _, s := range e.list {
			s.run = 0
		}
		dt = 0
	}
	e.lastTick = now
	for _, s := range e.list {
		for s.level > 0 && now.Sub(s.levelAt) >= RestoreLevelDecay {
			s.level--
			s.levelAt = s.levelAt.Add(RestoreLevelDecay)
		}
	}

	cs := e.evaluate(now)
	var a *cand
	if e.selected != nil {
		a = &cs[e.selected.index]
	}

	// Accumulators.
	anyDegrade := false
	for i := range cs {
		anyDegrade = anyDegrade || cs[i].degrade
	}
	e.degradeAcc = step(e.degradeAcc, dt, anyDegrade, e.p.Persist)
	for i := range cs {
		c := &cs[i]
		if c.restoreOn {
			c.st.restoreAcc = step(c.st.restoreAcc, dt, c.restore, e.hold(c.st))
		} else {
			c.st.restoreAcc = 0
		}
	}

	t := &tick{e: e, now: now, cs: cs, a: a}
	t.cooldownLeft = max(e.lastSwitch.Add(e.p.Cooldown).Sub(now), 0)
	for i := range cs {
		t.anyFresh = t.anyFresh || cs[i].fresh
	}
	// Common-mode outage: an endpoint with a loss run is not fresh itself, so
	// "no endpoint fresh" means no other endpoint is fresh either. Move the
	// run floor forward: only later losses count toward the outage rule.
	if !t.anyFresh {
		for _, s := range e.list {
			s.run = 0
		}
	}
	d := t.decide(anyDegrade)
	d.Record = t.record(gap, anyDegrade)
	return d
}

// evaluate computes estimates, costs, eligibility, freshness and the gated
// comparison against the active endpoint.
func (e *Engine) evaluate(now time.Time) []cand {
	cs := make([]cand, len(e.list))
	freshAge := 2 * time.Duration(len(e.list)) * e.p.Interval
	marginAbs := float64(e.p.MarginAbs) / float64(time.Millisecond)
	for i, s := range e.list {
		c := &cs[i]
		c.st = s
		c.est = s.estimate(e.sp)
		c.lossFactor, _ = lossTerm(e.p.LossWeight, c.est)
		c.cost = c.est.Latency * c.lossFactor
		c.biased = c.cost * (1 + e.p.OrderBias*float64(i))
		c.warm = s.ring.Len() >= e.p.MinSamples
		c.eligible = c.warm && c.est.Finite()
		last, ok := s.ring.Last()
		c.fresh = ok && last.Replied && now.Sub(last.At) <= freshAge
	}
	if e.selected == nil {
		return cs
	}
	a := &cs[e.selected.index]
	for i := range cs {
		b := &cs[i]
		if b == a {
			continue
		}
		b.hasGate = true
		b.gate = e.compare(a, b)
		g := b.gate.g
		b.degrade = a.warm && b.eligible && g >= 1+e.p.Margin && b.biased*(g-1) >= marginAbs
		b.restoreOn = e.p.WaitToRestore > 0 && i < a.st.index
		b.restore = b.restoreOn && a.warm && b.eligible && g >= 1
	}
	return cs
}

// tick holds one Tick's evaluation while the decision is made.
type tick struct {
	e            *Engine
	now          time.Time
	cs           []cand
	a            *cand
	cooldownLeft time.Duration
	anyFresh     bool
	// outage rule state for the record
	outageK, outageRun int
	outageTarget       *cand
	degradeTarget      *cand
}

func label(c *cand) string {
	return endpoints.Label(c.st.name, c.st.index) + " " + c.st.addr.String()
}

func secs(d time.Duration) string {
	return strconv.FormatFloat(d.Round(time.Millisecond).Seconds(), 'f', -1, 64)
}

// best returns the candidate passing ok that is preferred by better, with
// ties going to the earlier list position; nil if none.
func (t *tick) best(ok func(*cand) bool, better func(x, y *cand) bool) *cand {
	var b *cand
	for i := range t.cs {
		c := &t.cs[i]
		if c == t.a || !ok(c) {
			continue
		}
		if b == nil || better(c, b) {
			b = c
		}
	}
	return b
}

func lowerBiased(x, y *cand) bool { return x.biased < y.biased }

func higherG(x, y *cand) bool {
	return x.gate.g > y.gate.g || (x.gate.g == y.gate.g && x.biased < y.biased)
}

func (t *tick) switchTo(kind Kind, c *cand, reason string) Decision {
	d := Decision{Switch: true, Kind: kind, To: c.st.addr, Reason: reason}
	if t.a != nil {
		d.From = t.a.st.addr
	} else {
		d.From = t.e.removed
	}
	return d
}

func blocked(b Blocker, reason string) Decision {
	return Decision{Blocker: b, Reason: reason}
}

// guard applies the guards shared by every fired rule: all-down, cooldown
// (unless exempt) and freshness. target is the fresh target, or nil;
// stale names the best non-fresh target for the reason.
func (t *tick) guard(kind Kind, target, stale *cand, cooldown bool, reason string) Decision {
	if target == nil && !t.anyFresh {
		return blocked(BlockerAllDown, "all down: "+reason+", but no endpoint is fresh")
	}
	if cooldown && t.cooldownLeft > 0 {
		to := target
		if to == nil {
			to = stale
		}
		return blocked(BlockerCooldown, fmt.Sprintf("cooldown %ss left (%s to %s pending)", secs(t.cooldownLeft), kind, label(to)))
	}
	if target == nil {
		return blocked(BlockerNotFresh, fmt.Sprintf("target not fresh: %s (%s)", label(stale), reason))
	}
	return t.switchTo(kind, target, reason)
}

func (t *tick) decide(anyDegrade bool) Decision {
	e := t.e
	cs := t.cs
	finite := func(c *cand) bool { return c.est.Finite() }
	fresh := func(c *cand) bool { return c.fresh }

	// Rule 6: the selection was removed by a reload.
	if e.selected == nil && e.removed.IsValid() {
		target := t.best(func(c *cand) bool { return c.eligible && c.fresh }, lowerBiased)
		if target == nil {
			target = t.best(fresh, lowerBiased)
		}
		if target == nil {
			target = t.best(func(c *cand) bool { return c.eligible }, lowerBiased)
		}
		if target == nil {
			if t.best(func(c *cand) bool { return c.warm }, lowerBiased) == nil {
				return blocked(BlockerWarmingUp, "warming up: selected endpoint "+e.removed.String()+" was removed and no candidate is eligible or fresh yet")
			}
			return blocked(BlockerAllDown, "all down: selected endpoint "+e.removed.String()+" was removed and no candidate is eligible or fresh")
		}
		return t.switchTo(KindReload, target, "selected endpoint "+e.removed.String()+" was removed from the list")
	}

	// Rule 5: no listed selection (device on an unlisted endpoint).
	if t.a == nil {
		eligible := func(c *cand) bool { return c.eligible }
		stale := t.best(eligible, lowerBiased)
		if stale == nil {
			return blocked(BlockerWarmingUp, fmt.Sprintf("warming up: no listed selection and no candidate has %d valid samples yet", e.p.MinSamples))
		}
		target := t.best(func(c *cand) bool { return c.eligible && c.fresh }, lowerBiased)
		return t.guard(KindStartup, target, stale, true, "no listed selection, switching to the best eligible candidate")
	}
	a := t.a
	degrading := func(c *cand) bool { return c.degrade }
	t.degradeTarget = t.best(degrading, higherG)

	// Rule 1: outage.
	t.outageRun = a.st.run
	t.outageK = e.outageK(a.st)
	t.outageTarget = t.best(func(c *cand) bool { return c.eligible && c.fresh }, lowerBiased)
	if t.outageTarget == nil {
		t.outageTarget = t.best(func(c *cand) bool {
			return c.fresh && finite(c) && c.st.ring.Len() >= OutageStartupSamples
		}, lowerBiased)
	}
	if t.outageRun >= t.outageK {
		reason := fmt.Sprintf("outage: active %s lost %d probes in a row (K=%d)", label(a), t.outageRun, t.outageK)
		if t.outageTarget == nil {
			// Some candidate is fresh (otherwise the run would have been
			// reset as common-mode), but none has enough history.
			return blocked(BlockerWarmingUp, "warming up: "+reason+", and no fresh candidate has enough samples")
		}
		// The outage evidence must postdate the target's freshness evidence,
		// i.e. the active must have lost a probe while the target was
		// replying (e.g. the target recovered together with the active from a
		// shared upstream failure, while a third endpoint stayed fresh).
		lastLoss, _ := a.st.ring.Last()
		since := replyStreakStart(t.outageTarget.st.ring)
		if !lastLoss.At.After(since) {
			return blocked(BlockerOutageUnconfirmed, fmt.Sprintf(
				"outage run predates target's replies: %s lost %d in a row (K=%d), its last loss %ss before %s replied again; waiting for the active's next probe",
				label(a), t.outageRun, t.outageK, secs(since.Sub(lastLoss.At)), label(t.outageTarget)))
		}
		return t.guard(KindOutage, t.outageTarget, nil, true, reason)
	}

	// Rule 2: degradation.
	if anyDegrade && e.degradeAcc >= e.p.Persist {
		target := t.best(func(c *cand) bool { return c.degrade && c.fresh }, higherG)
		r := t.degradeTarget
		if target != nil {
			r = target
		}
		reason := fmt.Sprintf("degradation held %s/%s s: G(%s→%s) = %.3f ≥ %.3f",
			secs(e.degradeAcc), secs(e.p.Persist), label(a), label(r), r.gate.g, 1+e.p.Margin)
		return t.guard(KindDegrade, target, t.degradeTarget, true, reason)
	}

	// Rule 3: revert to an earlier endpoint.
	firedOK := func(c *cand) bool { return c.restore && c.st.restoreAcc >= e.hold(c.st) }
	if fired := t.best(firedOK, lowerBiased); fired != nil {
		target := t.best(func(c *cand) bool { return firedOK(c) && c.fresh }, lowerBiased)
		r := fired
		if target != nil {
			r = target
		}
		reason := fmt.Sprintf("restore: %s not worse than %s for %s/%s s (level %d)",
			label(r), label(a), secs(r.st.restoreAcc), secs(e.hold(r.st)), r.st.level)
		return t.guard(KindRestore, target, fired, true, reason)
	}

	// Nothing fired: name what is holding.
	switch {
	case !a.warm:
		return blocked(BlockerWarmingUp, fmt.Sprintf("warming up: active %s has %d/%d valid samples",
			label(a), a.st.ring.Len(), e.p.MinSamples))
	case !t.anyFresh:
		return blocked(BlockerAllDown, "all down: no endpoint replied recently")
	case anyDegrade:
		return blocked(BlockerPersist, fmt.Sprintf("persist %s/%s s (%s better: G %.3f)",
			secs(e.degradeAcc), secs(e.p.Persist), label(t.degradeTarget), t.degradeTarget.gate.g))
	}
	var holding *cand
	for i := range cs {
		c := &cs[i]
		if !c.restore {
			continue
		}
		if holding == nil || float64(c.st.restoreAcc)/float64(e.hold(c.st)) > float64(holding.st.restoreAcc)/float64(e.hold(holding.st)) {
			holding = c
		}
	}
	if holding != nil {
		return blocked(BlockerRestoreHold, fmt.Sprintf("restore hold %s/%s s for %s (level %d)",
			secs(holding.st.restoreAcc), secs(e.hold(holding.st)), label(holding), holding.st.level))
	}
	if t.best(func(c *cand) bool { return c.eligible }, lowerBiased) == nil {
		return blocked(BlockerNoCandidate, "no other eligible candidate")
	}
	return blocked(BlockerNothingBetter, "nothing better beyond noise")
}

// record builds the full decision record.
func (t *tick) record(gap, anyDegrade bool) Record {
	e := t.e
	r := Record{
		At:           t.now,
		Removed:      e.removed,
		Gap:          gap,
		CooldownLeft: t.cooldownLeft,
		Endpoints:    make([]EndpointView, len(t.cs)),
	}
	if t.a != nil {
		r.Active = t.a.st.addr
	}
	for i := range t.cs {
		c := &t.cs[i]
		v := EndpointView{
			Addr:           c.st.addr,
			Index:          i,
			Name:           endpoints.DisplayName(c.st.name, i),
			Active:         c == t.a,
			Samples:        c.est.Samples,
			Replies:        c.est.Replies,
			Invalid:        c.st.invalid,
			Loss:           Float(c.est.Loss),
			LossSE:         Float(c.est.LossSE),
			RTTMean:        Float(c.est.RTTMean),
			RTTStd:         Float(c.est.RTTStd),
			Latency:        Float(c.est.Latency),
			LatencySE:      Float(c.est.LatencySE),
			LossFactor:     Float(c.lossFactor),
			Cost:           Float(c.cost),
			BiasedCost:     Float(c.biased),
			Eligible:       c.eligible,
			Fresh:          c.fresh,
			TrailingLosses: c.st.run,
			RestoreLevel:   c.st.level,
			LastInvalid:    c.st.lastInvalid,
		}
		if c.hasGate {
			v.Gate = c.gate.view()
		}
		if last, ok := c.st.ring.Last(); ok {
			v.Last = &last
		}
		r.Endpoints[i] = v
	}

	switch {
	case e.selected == nil && e.removed.IsValid():
		r.Rules = append(r.Rules, RuleState{Rule: RuleReload, Active: true})
	case t.a == nil:
		r.Rules = append(r.Rules, RuleState{Rule: RuleStartup, Active: true})
	default:
		out := RuleState{Rule: RuleOutage, Run: t.outageRun, K: t.outageK, Active: t.outageRun > 0, Fired: t.outageRun >= t.outageK}
		if t.outageTarget != nil {
			out.Target = t.outageTarget.st.addr
		}
		deg := RuleState{Rule: RuleDegrade, Value: e.degradeAcc, Hold: e.p.Persist, Active: anyDegrade,
			Fired: anyDegrade && e.degradeAcc >= e.p.Persist}
		if t.degradeTarget != nil {
			deg.Target = t.degradeTarget.st.addr
		}
		r.Rules = append(r.Rules, out, deg)
		for i := range t.cs {
			c := &t.cs[i]
			if !c.restoreOn {
				continue
			}
			h := e.hold(c.st)
			r.Rules = append(r.Rules, RuleState{Rule: RuleRestore, Target: c.st.addr, Value: c.st.restoreAcc,
				Hold: h, Level: c.st.level, Active: c.restore, Fired: c.restore && c.st.restoreAcc >= h})
		}
	}
	return r
}
