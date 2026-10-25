package policy

import (
	"math"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/bjin/wgsteer/internal/stats"
)

// Calibration table from synthetic deterministic sample
// sequences: losses spread evenly at the exact rate, RTTs alternating
// mean±sd (so the sample standard deviation is sd), bimodal tails spread
// evenly among replies.

// steadyPath is deterministic: the k-th probe of the endpoint is lost when
// the running loss count crosses an integer; replies alternate mean−sd and
// mean+sd, and a fraction tail of them is delayed by extra.
func steadyPath(mean, sd time.Duration, loss, tail float64, extra time.Duration) path {
	k, r := 0, 0
	return func(*rand.Rand, time.Duration) (bool, time.Duration) {
		lost := math.Floor(float64(k+1)*loss+0.5) > math.Floor(float64(k)*loss+0.5)
		k++
		if lost {
			return false, 0
		}
		rtt := mean - sd
		if r%2 == 1 {
			rtt = mean + sd
		}
		if math.Floor(float64(r+1)*tail+0.5) > math.Floor(float64(r)*tail+0.5) {
			rtt += extra
		}
		r++
		return true, rtt
	}
}

func steady(meanMS float64, lossRate float64) path {
	return steadyPath(time.Duration(meanMS*float64(time.Millisecond)), 5*time.Millisecond, lossRate, 0, 0)
}

type calibCase struct {
	name string
	// paths by list position; active is the starting selection.
	paths  func() []path
	active int
	// want: "stay", "switch" (degradation or outage away from active),
	// "allowed" (a switch to #0 by any rule), "revert" (restore to #0 after
	// wait-to-restore), "none" (no switch at all).
	want string
}

var calibCases = []calibCase{
	{"S1", func() []path { return []path{steady(150, 0.05), steady(170, 0.05)} }, 0, "stay"},
	{"S2", func() []path { return []path{steady(150, 0.30), steady(180, 0.05)} }, 0, "switch"},
	{"S3", func() []path {
		return []path{steadyPath(150*time.Millisecond, 5*time.Millisecond, 0.03, 0.3, 100*time.Millisecond), steady(165, 0.03)}
	}, 0, "switch"},
	{"S4", func() []path { return []path{steady(150, 0.10), steady(180, 0.03)} }, 0, "stay"},
	{"S5", func() []path { return []path{steady(150, 0.20), steady(180, 0.03)} }, 0, "switch"},
	{"S4'", func() []path { return []path{steady(150, 0.10), steady(180, 0.03)} }, 1, "allowed"},
	{"S6", func() []path { return []path{steady(150, 0.04), steady(165, 0.04)} }, 1, "revert"},
	{"S7", func() []path { return []path{steady(160, 0.05), steady(160, 0.05)} }, 1, "revert"},
	{"S7 from #0", func() []path { return []path{steady(160, 0.05), steady(160, 0.05)} }, 0, "stay"},
	{"S8", func() []path { return []path{steady(210, 0.05), steady(165, 0.05)} }, 0, "switch"},
	{"S9", func() []path { return []path{steady(175, 0.05), steady(165, 0.05)} }, 0, "stay"},
	{"S10", func() []path { return []path{steady(150, 1), steady(165, 1)} }, 0, "none"},
}

// steadyGate returns the decision after a full history of steady-state
// samples (no switch committed), for the point-estimate G of the candidate.
func steadyGate(p Params, c calibCase) Decision {
	s := newSim(p, 1, c.paths(), c.active)
	for s.slot < p.History*len(s.paths) {
		i := s.slot % len(s.paths)
		ok, rtt := s.paths[i](nil, 0)
		s.eng.Record(s.addrs[i], stats.Sample{At: simEpoch.Add(s.now()), Replied: ok, RTT: rtt})
		s.slot++
	}
	return s.eng.Tick(simEpoch.Add(s.now()))
}

func TestCalibration(t *testing.T) {
	p := DefaultParams()
	const horizon = 3 * time.Hour
	for _, c := range calibCases {
		t.Run(c.name, func(t *testing.T) {
			d := steadyGate(p, c)
			cand := d.Record.Endpoints[1-c.active]
			act := d.Record.Endpoints[c.active]
			g := float64(cand.Gate.G)
			t.Logf("%s: cost active %.0f (biased %.0f) / cand %.0f (biased %.0f); p̂ %.3f/%.3f; G(active→cand) %.3f (r_lat %.3f→%.3f, r_loss %.3f→%.3f)",
				c.name, act.Cost, act.BiasedCost, cand.Cost, cand.BiasedCost, act.Loss, cand.Loss, g,
				cand.Gate.RLat, cand.Gate.RLatGated, cand.Gate.RLoss, cand.Gate.RLossGated)

			s := newSim(p, 1, c.paths(), c.active)
			s.runFor(horizon)
			switch c.want {
			case "stay", "none":
				if c.want == "stay" && g >= 1+p.Margin {
					t.Errorf("steady-state G = %.3f, want < %.3f", g, 1+p.Margin)
				}
				if len(s.events) != 0 {
					t.Errorf("switched: %+v", s.events)
				}
			case "switch":
				if g < 1+p.Margin {
					t.Errorf("steady-state G = %.3f, want ≥ %.3f", g, 1+p.Margin)
				}
				if len(s.events) == 0 || s.events[0].From != c.active || s.events[0].Kind != KindDegrade {
					t.Fatalf("want a degradation switch away from #%d, got %+v", c.active, s.events)
				}
				// From an empty history the estimate reaches the steady state
				// once the ring is full; then persist.
				if limit := time.Duration(p.History*len(s.paths))*p.Interval + p.Persist + 2*time.Minute; s.events[0].At > limit {
					t.Errorf("switch at %v, want within %v", s.events[0].At, limit)
				}
			case "allowed":
				if g < 1 {
					t.Errorf("steady-state G = %.3f, want ≥ 1", g)
				}
				if len(s.events) == 0 || s.events[0].To != 0 {
					t.Fatalf("want a switch to #0, got %+v", s.events)
				}
			case "revert":
				if g < 1 || g >= 1+p.Margin {
					t.Errorf("steady-state G = %.3f, want in [1, %.3f)", g, 1+p.Margin)
				}
				if len(s.events) == 0 || s.events[0].Kind != KindRestore || s.events[0].To != 0 {
					t.Fatalf("want a restore to #0, got %+v", s.events)
				}
				// Eligibility is observed at tick granularity: the tick that
				// first sees it already credits one interval.
				elig := max(s.eligibleAt[0], s.eligibleAt[1]) - p.Interval
				if dt := s.events[0].At - elig; dt < p.WaitToRestore || dt > p.WaitToRestore*3/2 {
					t.Errorf("restore %v after eligibility, want in [%v, %v]", dt, p.WaitToRestore, p.WaitToRestore*3/2)
				}
				if len(s.events) != 1 {
					t.Errorf("switched again after the restore: %+v", s.events[1:])
				}
			}
		})
	}
}
