package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"sync"
	"testing"
	"time"
)

// TestSimParams runs the TestTargets scenarios with the parameters in
// WGSTEER_SIM_PARAMS (JSON Params, durations in nanoseconds, missing fields
// from DefaultParams) and prints the measurements as one JSON line prefixed
// "SIMPARAMS ". It asserts nothing: tools/tune.py checks tuned flags against
// the design targets with it (the recorded paths of a dry-run rarely contain
// lossy or near-equal conditions). Skipped unless the variable is set.
func TestSimParams(t *testing.T) {
	raw := os.Getenv("WGSTEER_SIM_PARAMS")
	if raw == "" {
		t.Skip("WGSTEER_SIM_PARAMS not set")
	}
	p := DefaultParams()
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatal(err)
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	seeds := func(base uint64, n int) []uint64 {
		s := make([]uint64, n)
		for i := range s {
			s[i] = base + uint64(i)
		}
		return s
	}
	// Step scenarios warm up for 3 half-lives (at least simWarmup), so a
	// long half-life starts from a steady-state window.
	warm := max(simWarmup, time.Duration(3*p.HalfLife*simEndpoints)*p.Interval)
	type detection struct {
		Median float64 `json:"median_s"`
		Max    float64 `json:"max_s"`
		Missed int     `json:"missed"`
		Seeds  int     `json:"seeds"`
	}
	detect := func(base float64, after path, seed0 uint64, limit time.Duration) any {
		d := detection{Seeds: 12}
		var ds []float64
		for _, seed := range seeds(seed0, d.Seeds) {
			s := newSim(p, seed, equalPaths(simEndpoints, 150*ms, base), 0)
			s.runFor(warm)
			s.events = nil
			s.paths[s.active()] = after
			if at := s.runUntilSwitch(limit); at >= 0 {
				ds = append(ds, at.Seconds())
			} else {
				d.Missed++
			}
		}
		if len(ds) > 0 {
			d.Median, d.Max = median(ds), slices.Max(ds)
		}
		return d
	}
	perRun := func(n, runs int) float64 { return float64(n) / float64(runs) }
	scenarios := map[string]func() any{
		"equal_5pct_switches_per_24h": func() any {
			n := 0
			for _, seed := range seeds(100, 24) {
				n += len(runEqual(p, seed, 0.05, 24*time.Hour).events)
			}
			return perRun(n, 24)
		},
		"equal_10pct_degrade_per_12h": func() any {
			n := 0
			for _, seed := range seeds(200, 24) {
				n += runEqual(p, seed, 0.10, 12*time.Hour).count(0, KindDegrade)
			}
			return perRun(n, 24)
		},
		"step_60ms":        func() any { return detect(0.05, gaussian(210*ms, 5*ms, 0.05), 300, 20*time.Minute) },
		"tail_30pct_100ms": func() any { return detect(0.03, bimodal(150*ms, 5*ms, 0.3, 100*ms, 0.03), 400, 20*time.Minute) },
		"loss_5_to_50pct":  func() any { return detect(0.05, gaussian(150*ms, 5*ms, 0.5), 500, 20*time.Minute) },
		"loss_5_to_30pct":  func() any { return detect(0.05, gaussian(150*ms, 5*ms, 0.3), 600, 30*time.Minute) },
		"loss_5_to_100pct": func() any { return detect(0.05, gaussian(150*ms, 5*ms, 1), 650, 10*time.Minute) },
		"step_20ms_per_3h": func() any {
			n := 0
			for _, seed := range seeds(700, 24) {
				s := newSim(p, seed, equalPaths(simEndpoints, 150*ms, 0.05), 0)
				s.runFor(warm)
				s.events = nil
				s.paths[s.active()] = gaussian(170*ms, 5*ms, 0.05)
				s.runFor(3 * time.Hour)
				n += len(s.events)
			}
			return perRun(n, 24)
		},
		"restore_after_eligible_s": func() any {
			var ds []float64
			for _, seed := range seeds(800, 12) {
				d, _ := runRecovery(p, seed, gaussian(150*ms, 5*ms, 0.05), gaussian(150*ms, 5*ms, 0.05), 3*time.Hour+8*p.WaitToRestore)
				ds = append(ds, d.Seconds()) // -1: no restore to #0 as the first switch
			}
			return ds
		},
		"reverts_to_worse_0": func() any {
			n := 0
			for _, seed := range seeds(1100, 12) {
				_, s := runRecovery(p, seed, gaussian(170*ms, 5*ms, 0.05), gaussian(150*ms, 5*ms, 0.05), 3*time.Hour)
				s.runFor(3*time.Hour - s.now())
				for _, e := range s.events {
					if e.To == 0 {
						n++
					}
				}
			}
			return n
		},
		"near_margin_switches_per_h": func() any {
			n := 0
			for _, seed := range seeds(1200, 24) {
				ps := equalPaths(simEndpoints, 150*ms, 0.05)
				ps[0] = gaussian(150*ms, 5*ms, 0.10)
				s := newSim(p, seed, ps, 0)
				s.runFor(12 * time.Hour)
				n += len(s.events)
			}
			return perRun(n, 24*12)
		},
		"all_down_per_12h": func() any {
			out, all := 0, 0
			for _, seed := range seeds(1600, 24) {
				ps := equalPaths(simEndpoints, 150*ms, 0.05)
				for i := range ps {
					ps[i] = withAllDown(ps[i], 30*time.Minute+time.Second, time.Minute)
				}
				s := newSim(p, seed, ps, 0)
				s.runFor(12 * time.Hour)
				out += s.count(0, KindOutage)
				all += len(s.events)
			}
			return map[string]float64{"outage": perRun(out, 24), "all": perRun(all, 24)}
		},
		"bursty_degrade_per_12h": func() any {
			n := 0
			for _, seed := range seeds(1300, 12) {
				ps := equalPaths(simEndpoints, 150*ms, 0.03)
				ge := &gilbertElliott{mean: 150 * ms, sd: 5 * ms, goodLoss: 0.03, badLoss: 0.5, goodMean: 9 * time.Minute, badMean: time.Minute}
				ps[0] = ge.path
				s := newSim(p, seed, ps, 0)
				s.runFor(12 * time.Hour)
				n += s.count(0, KindDegrade)
			}
			return perRun(n, 12)
		},
	}
	out := make(map[string]any, len(scenarios))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for name, f := range scenarios {
		wg.Go(func() {
			v := f()
			mu.Lock()
			out[name] = v
			mu.Unlock()
		})
	}
	wg.Wait()
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("SIMPARAMS " + string(b))
}
