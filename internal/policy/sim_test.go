package policy

import (
	"math"
	"math/rand/v2"
	"net/netip"
	"slices"
	"time"

	"github.com/bjin/wgsteer/internal/endpoints"
	"github.com/bjin/wgsteer/internal/stats"
)

// Simulation harness: synthetic ground truth per endpoint
// drives the real Engine on a fake clock with the exact probe schedule
// (round-robin, one endpoint per slot, Tick after every slot, Commit on every
// proposed switch, RTT above the timeout counts as loss).

const simTimeout = 500 * time.Millisecond

var simEpoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// path draws one probe result at elapsed simulated time.
type path func(rng *rand.Rand, at time.Duration) (replied bool, rtt time.Duration)

func normalRTT(rng *rand.Rand, mean, sd time.Duration) time.Duration {
	return max(mean+time.Duration(rng.NormFloat64()*float64(sd)), time.Millisecond)
}

// gaussian: i.i.d. loss, normal RTT.
func gaussian(mean, sd time.Duration, loss float64) path {
	return func(rng *rand.Rand, _ time.Duration) (bool, time.Duration) {
		if rng.Float64() < loss {
			return false, 0
		}
		return true, normalRTT(rng, mean, sd)
	}
}

// bimodal: a fraction tail of the replies is delayed by extra.
func bimodal(mean, sd time.Duration, tail float64, extra time.Duration, loss float64) path {
	return func(rng *rand.Rand, _ time.Duration) (bool, time.Duration) {
		if rng.Float64() < loss {
			return false, 0
		}
		rtt := normalRTT(rng, mean, sd)
		if rng.Float64() < tail {
			rtt += extra
		}
		return true, rtt
	}
}

// gilbertElliott is a continuous-time two-state loss model: exponentially
// distributed good and bad periods with their own loss rates.
type gilbertElliott struct {
	mean, sd          time.Duration
	goodLoss, badLoss float64
	goodMean, badMean time.Duration
	bad               bool
	next              time.Duration
}

func (g *gilbertElliott) path(rng *rand.Rand, at time.Duration) (bool, time.Duration) {
	if g.next == 0 { // start in the good state
		g.next = time.Duration(rng.ExpFloat64() * float64(g.goodMean))
	}
	for at >= g.next {
		g.bad = !g.bad
		m := g.goodMean
		if g.bad {
			m = g.badMean
		}
		g.next += time.Duration(rng.ExpFloat64() * float64(m))
	}
	loss := g.goodLoss
	if g.bad {
		loss = g.badLoss
	}
	if rng.Float64() < loss {
		return false, 0
	}
	return true, normalRTT(rng, g.mean, g.sd)
}

type simEvent struct {
	At       time.Duration
	Kind     Kind
	From, To int
	// Level is the restore level of From after the switch; Hold the hold
	// time of a restore target at switch time.
	Level int
	Hold  time.Duration
}

type sim struct {
	p      Params
	eng    *Engine
	addrs  []netip.AddrPort
	paths  []path
	rng    *rand.Rand
	slot   int
	events []simEvent
	last   Decision
	// eligibleAt is when each endpoint first became eligible (-1 if not yet).
	eligibleAt []time.Duration
}

func simAddrs(n int) []netip.AddrPort {
	out := make([]netip.AddrPort, n)
	for i := range out {
		out[i] = netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(10 + i)}), 51820)
	}
	return out
}

// newSim starts the daemon at simEpoch with an empty history, selection
// paths[start] (or none if start < 0).
func newSim(p Params, seed uint64, paths []path, start int) *sim {
	s := &sim{
		p:          p,
		addrs:      simAddrs(len(paths)),
		paths:      paths,
		rng:        rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)),
		eligibleAt: slices.Repeat([]time.Duration{-1}, len(paths)),
	}
	var sel netip.AddrPort
	if start >= 0 {
		sel = s.addrs[start]
	}
	eng, err := New(p, endpoints.Unnamed(s.addrs), sel, simEpoch)
	if err != nil {
		panic(err)
	}
	s.eng = eng
	return s
}

func (s *sim) now() time.Duration { return time.Duration(s.slot) * s.p.Interval }

func (s *sim) active() int {
	sel := s.eng.Selected()
	return slices.Index(s.addrs, sel)
}

// stepSlot runs one probe slot and the Tick after it.
func (s *sim) stepSlot() {
	i := s.slot % len(s.addrs)
	sent := s.now()
	ok, rtt := s.paths[i](s.rng, sent)
	if rtt > simTimeout {
		ok, rtt = false, 0
	}
	at := simEpoch.Add(sent)
	s.eng.Record(s.addrs[i], stats.Sample{At: at, Replied: ok, RTT: rtt})
	s.slot++
	now := simEpoch.Add(s.now())
	d := s.eng.Tick(now)
	for j, v := range d.Record.Endpoints {
		if v.Eligible && s.eligibleAt[j] < 0 {
			s.eligibleAt[j] = s.now()
		}
	}
	if d.Switch {
		ev := simEvent{At: s.now(), Kind: d.Kind, From: slices.Index(s.addrs, d.From), To: slices.Index(s.addrs, d.To)}
		for _, r := range d.Record.Rules {
			if r.Rule == RuleRestore && r.Target == d.To {
				ev.Hold = r.Hold
			}
		}
		s.eng.Commit(d, now)
		if ev.From >= 0 {
			ev.Level = s.eng.byAddr[s.addrs[ev.From]].level
		}
		s.events = append(s.events, ev)
	}
	s.last = d
}

func (s *sim) runFor(d time.Duration) {
	end := s.now() + d
	for s.now() < end {
		s.stepSlot()
	}
}

// runUntilSwitch runs until the next switch or limit; it returns the switch
// time relative to the call, or -1.
func (s *sim) runUntilSwitch(limit time.Duration) time.Duration {
	start, n := s.now(), len(s.events)
	for s.now()-start < limit {
		s.stepSlot()
		if len(s.events) > n {
			return s.now() - start
		}
	}
	return -1
}

func (s *sim) count(since time.Duration, kinds ...Kind) int {
	n := 0
	for _, ev := range s.events {
		if ev.At >= since && (len(kinds) == 0 || slices.Contains(kinds, ev.Kind)) {
			n++
		}
	}
	return n
}

// withAllDown wraps p with periodic episodes in which every probe is lost
// (local uplink or server down): the first down of every period.
func withAllDown(p path, period, down time.Duration) path {
	return func(rng *rand.Rand, at time.Duration) (bool, time.Duration) {
		if at%period < down {
			// Draw anyway so the episode does not shift p's random stream.
			p(rng, at)
			return false, 0
		}
		return p(rng, at)
	}
}

func equalPaths(n int, mean time.Duration, loss float64) []path {
	ps := make([]path, n)
	for i := range ps {
		ps[i] = gaussian(mean, 5*time.Millisecond, loss)
	}
	return ps
}

// Scenario runners shared by the target tests (and used to tune defaults).

const simEndpoints = 5

// simWarmup fills every ring before a step change (100 samples × 5 s).
const simWarmup = 10 * time.Minute

// runEqual: equal paths, start on #0; returns switches by kind.
func runEqual(p Params, seed uint64, loss float64, d time.Duration) *sim {
	s := newSim(p, seed, equalPaths(simEndpoints, 150*time.Millisecond, loss), 0)
	s.runFor(d)
	return s
}

// runStep: equal 150±5 ms paths at baseLoss; after the warmup the active
// endpoint changes to after. It returns the time from the change to the
// first switch away (or -1 within limit) and the sim.
func runStep(p Params, seed uint64, baseLoss float64, after path, limit time.Duration) (time.Duration, *sim) {
	s := newSim(p, seed, equalPaths(simEndpoints, 150*time.Millisecond, baseLoss), 0)
	s.runFor(simWarmup)
	s.events = nil
	s.paths[s.active()] = after
	return s.runUntilSwitch(limit), s
}

// runRecovery: active #1 from start, #0 given by p0, others by pOther.
// It returns the restore delay after #0 became eligible, or -1, and the sim.
func runRecovery(p Params, seed uint64, p0, pOther path, limit time.Duration) (time.Duration, *sim) {
	paths := make([]path, simEndpoints)
	paths[0] = p0
	for i := 1; i < simEndpoints; i++ {
		paths[i] = pOther
	}
	s := newSim(p, seed, paths, 1)
	s.runUntilSwitch(limit)
	if len(s.events) == 0 || s.events[0].To != 0 || s.events[0].Kind != KindRestore || s.eligibleAt[0] < 0 {
		return -1, s
	}
	return s.events[0].At - s.eligibleAt[0], s
}

func median(xs []float64) float64 {
	ys := slices.Clone(xs)
	slices.Sort(ys)
	n := len(ys)
	if n == 0 {
		return math.NaN()
	}
	if n%2 == 1 {
		return ys[n/2]
	}
	return (ys[n/2-1] + ys[n/2]) / 2
}
