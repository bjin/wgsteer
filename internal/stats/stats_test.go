package stats

import (
	"math"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)

func reply(i int, rtt time.Duration) Sample {
	return Sample{At: t0.Add(time.Duration(i) * time.Second), Replied: true, RTT: rtt}
}

func loss(i int) Sample { return Sample{At: t0.Add(time.Duration(i) * time.Second)} }

func near(t *testing.T, name string, got, want, tol float64) {
	t.Helper()
	if math.Abs(got-want) > tol {
		t.Errorf("%s = %.6g, want %.6g ±%g", name, got, want, tol)
	}
}

var defaults = Params{HalfLife: 30, PriorMean: DefaultPriorMean, PriorWeight: DefaultPriorWeight, JitterWeight: 1}

func TestRingOrderEvictionAndRuns(t *testing.T) {
	r := NewRing(3)
	if _, ok := r.Last(); ok || r.Len() != 0 || r.TrailingLosses() != 0 {
		t.Fatal("empty ring not empty")
	}
	for i := range 5 {
		r.Add(reply(i, time.Duration(i+1)*time.Millisecond))
	}
	if r.Len() != 3 || r.Cap() != 3 {
		t.Fatalf("len %d cap %d", r.Len(), r.Cap())
	}
	for i, want := range []time.Duration{5, 4, 3} {
		if got := r.At(i).RTT; got != want*time.Millisecond {
			t.Errorf("At(%d) = %v, want %vms", i, got, want)
		}
	}
	r.Add(loss(5))
	r.Add(loss(6))
	if got := r.TrailingLosses(); got != 2 {
		t.Errorf("TrailingLosses = %d, want 2", got)
	}
	if last, _ := r.Last(); last.Replied || !last.At.Equal(t0.Add(6*time.Second)) {
		t.Errorf("Last = %+v", last)
	}
	r.Add(loss(7))
	if got := r.TrailingLosses(); got != 3 {
		t.Errorf("TrailingLosses on all-loss ring = %d, want 3", got)
	}
	r.Reset()
	if r.Len() != 0 {
		t.Error("Reset kept samples")
	}
	defer func() {
		if recover() == nil {
			t.Error("At out of range did not panic")
		}
	}()
	r.At(0)
}

func TestEstimateDecayWeightsAndNEff(t *testing.T) {
	r := NewRing(100)
	for i := range 100 {
		r.Add(reply(i, 150*time.Millisecond))
	}
	e := defaults.Estimate(r, 0)
	var sw, sw2 float64
	for a := range 100 {
		w := math.Exp2(-float64(a) / 30)
		sw += w
		sw2 += w * w
	}
	near(t, "SumW formula", e.SumW, sw, 1e-9)
	near(t, "SumW ≈39.4", e.SumW, 39.4, 0.1)
	near(t, "NEff formula", e.NEff, sw*sw/sw2, 1e-9)
	near(t, "NEff ≈70.8", e.NEff, 70.8, 0.2)
	near(t, "NEffReplied", e.NEffReplied, e.NEff, 1e-9)
	if e.Samples != 100 || e.Replies != 100 {
		t.Errorf("counts %d/%d", e.Samples, e.Replies)
	}
	// No losses: only the prior pseudo-count a = 0.2 remains.
	near(t, "Loss", e.Loss, 0.2/(sw+4), 1e-12)
	near(t, "RTTMean", e.RTTMean, 150, 1e-9)
	near(t, "RTTStd", e.RTTStd, 0, 1e-9)
	near(t, "LatencySE", e.LatencySE, 0, 1e-9)
}

func TestEstimatePriorAndLossSE(t *testing.T) {
	e := defaults.Estimate(NewRing(10), 0)
	near(t, "empty Loss", e.Loss, 0.05, 1e-12)
	near(t, "empty LossSE", e.LossSE, math.Sqrt(0.05*0.95/4), 1e-12)
	if !math.IsInf(e.Latency, 1) || e.Finite() {
		t.Errorf("empty ring latency %v, want +Inf", e.Latency)
	}

	// Steady 5% loss: one loss every 20 samples on a full ring.
	r := NewRing(100)
	for i := range 100 {
		if i%20 == 10 {
			r.Add(loss(i))
		} else {
			r.Add(reply(i, 150*time.Millisecond))
		}
	}
	e = defaults.Estimate(r, 0)
	var lostW float64
	for a := range 100 {
		if !r.At(a).Replied {
			lostW += math.Exp2(-float64(a) / 30)
		}
	}
	p := (lostW + 0.2) / (e.SumW + 4)
	near(t, "Loss", e.Loss, p, 1e-12)
	near(t, "LossSE", e.LossSE, math.Sqrt(p*(1-p)/(e.NEff+4)), 1e-12)
	// ±2.6 pp at 5%.
	near(t, "LossSE at 5%", math.Sqrt(0.05*0.95/(e.NEff+4)), 0.025, 0.002)

	// One new loss raises p̂ by about 1/(Σw+4) ≈ 2.3 pp.
	before := e.Loss
	r.Add(loss(100))
	after := defaults.Estimate(r, 0).Loss
	near(t, "single loss step", after-before, 1/(e.SumW+4), 0.003)
}

func TestEstimateWeightedRTT(t *testing.T) {
	p := Params{HalfLife: 1, PriorMean: 0.05, PriorWeight: 4, JitterWeight: 2}
	r := NewRing(4)
	r.Add(reply(0, 200*time.Millisecond)) // age 1, w = 0.5
	r.Add(reply(1, 100*time.Millisecond)) // age 0, w = 1
	e := p.Estimate(r, 0)
	mean := (100 + 0.5*200) / 1.5
	v := (1*(100-mean)*(100-mean) + 0.5*(200-mean)*(200-mean)) / (1.5 - 1.25/1.5)
	near(t, "RTTMean", e.RTTMean, mean, 1e-9)
	near(t, "RTTStd", e.RTTStd, math.Sqrt(v), 1e-9)
	near(t, "NEffReplied", e.NEffReplied, 1.5*1.5/1.25, 1e-12)
	near(t, "Latency", e.Latency, mean+2*math.Sqrt(v), 1e-9)
	near(t, "LatencySE", e.LatencySE, math.Sqrt(v/(1.5*1.5/1.25)*(1+4.0/2)), 1e-9)

	// Losses contribute to the loss estimate only.
	r.Add(loss(2))
	e2 := p.Estimate(r, 0)
	near(t, "RTTMean with loss", e2.RTTMean, mean, 1e-9)
	if e2.Replies != 2 || e2.Samples != 3 {
		t.Errorf("counts %d/%d", e2.Replies, e2.Samples)
	}

	// A single reply has no spread.
	one := NewRing(4)
	one.Add(reply(0, 80*time.Millisecond))
	e3 := p.Estimate(one, 0)
	near(t, "single RTTStd", e3.RTTStd, 0, 0)
	near(t, "single Latency", e3.Latency, 80, 1e-9)
}

func TestEstimateNoRepliesIsInfinite(t *testing.T) {
	r := NewRing(10)
	for i := range 10 {
		r.Add(loss(i))
	}
	e := defaults.Estimate(r, 0)
	if !math.IsInf(e.Latency, 1) || !math.IsInf(e.LatencySE, 1) || e.Finite() {
		t.Errorf("all-loss latency %v ± %v, want +Inf", e.Latency, e.LatencySE)
	}
	near(t, "all-loss Loss", e.Loss, (e.SumW+0.2)/(e.SumW+4), 1e-12)
}

func TestEstimateSkipNewestEqualsEarlierEstimate(t *testing.T) {
	r := NewRing(50)
	for i := range 30 {
		if i%7 == 3 {
			r.Add(loss(i))
		} else {
			r.Add(reply(i, time.Duration(140+i%5)*time.Millisecond))
		}
	}
	base := defaults.Estimate(r, 0)
	for i := 30; i < 35; i++ {
		r.Add(loss(i))
	}
	if got := r.TrailingLosses(); got != 5 {
		t.Fatalf("TrailingLosses = %d", got)
	}
	skipped := defaults.Estimate(r, r.TrailingLosses())
	if skipped != base {
		t.Errorf("skip estimate %+v\nwant %+v", skipped, base)
	}
	if full := defaults.Estimate(r, 0); full.Loss <= base.Loss {
		t.Errorf("full loss %v not above base %v", full.Loss, base.Loss)
	}
	if e := defaults.Estimate(r, 1000); e.Samples != 0 || e.Loss != 0.05 {
		t.Errorf("skip beyond length: %+v", e)
	}
}
