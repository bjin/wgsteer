package stats

import "math"

// Prior defaults: a Beta prior with mean 5% and the weight of 4
// samples keeps the loss estimate off zero and damps sparse histories.
const (
	DefaultPriorMean   = 0.05
	DefaultPriorWeight = 4
)

// Params configures the estimator.
type Params struct {
	// HalfLife is the recency half-life in samples of the endpoint.
	HalfLife float64
	// PriorMean and PriorWeight define the Beta prior of the loss rate:
	// a = PriorMean*PriorWeight, b = (1-PriorMean)*PriorWeight.
	PriorMean   float64
	PriorWeight float64
	// JitterWeight is k in the latency term mean + k*sigma.
	JitterWeight float64
}

// Estimate is the recency-weighted summary of a ring. RTT-derived values are
// in milliseconds.
type Estimate struct {
	// Samples and Replies count the included valid samples and their replies.
	Samples, Replies int
	// SumW is the total weight; NEff the variance-equivalent sample count
	// (Σw)²/Σw²; NEffReplied the same over replied samples only.
	SumW, NEff, NEffReplied float64
	// Loss is the posterior mean loss rate p̂ and LossSE = √(p̂(1−p̂)/(NEff+PriorWeight)).
	Loss, LossSE float64
	// RTTMean and RTTStd are the weighted mean and standard deviation over
	// replies (0 without replies).
	RTTMean, RTTStd float64
	// Latency is RTTMean + k·RTTStd and LatencySE its delta-method standard
	// error √(σ²/NEffReplied · (1 + k²/2)). Both are +Inf without replies.
	Latency, LatencySE float64
}

// Finite reports whether the estimate has a finite latency term, i.e. at
// least one reply in the window.
func (e Estimate) Finite() bool { return e.Replies > 0 }

// Estimate summarizes r, excluding its skipNewest newest samples. Ages are
// counted from the newest included sample (age 0), so the result equals the
// estimate the ring had before those samples arrived (used for the outage
// base rate, which must exclude the trailing loss run).
func (p Params) Estimate(r *Ring, skipNewest int) Estimate {
	skipNewest = max(skipNewest, 0)
	decay := math.Exp2(-1 / p.HalfLife)
	var (
		e                  Estimate
		sumW, sumW2, lostW float64
		repW, repW2        float64
		mean, m2           float64 // West's weighted incremental mean/variance
		w                  = 1.0
	)
	for i := skipNewest; i < r.Len(); i++ {
		s := r.At(i)
		e.Samples++
		sumW += w
		sumW2 += w * w
		if s.Replied {
			e.Replies++
			x := float64(s.RTT) / 1e6
			repW += w
			repW2 += w * w
			d := x - mean
			mean += w / repW * d
			m2 += w * d * (x - mean)
		} else {
			lostW += w
		}
		w *= decay
	}
	e.SumW = sumW
	if sumW2 > 0 {
		e.NEff = sumW * sumW / sumW2
	}
	a := p.PriorMean * p.PriorWeight
	e.Loss = (lostW + a) / (sumW + p.PriorWeight)
	e.LossSE = math.Sqrt(e.Loss * (1 - e.Loss) / (e.NEff + p.PriorWeight))
	if e.Replies == 0 {
		e.Latency = math.Inf(1)
		e.LatencySE = math.Inf(1)
		return e
	}
	e.NEffReplied = repW * repW / repW2
	e.RTTMean = mean
	// Unbiased variance for reliability weights: Σw(x−μ)² / (V1 − V2/V1).
	if den := repW - repW2/repW; den > 1e-12*repW {
		e.RTTStd = math.Sqrt(max(m2, 0) / den)
	}
	k := p.JitterWeight
	e.Latency = e.RTTMean + k*e.RTTStd
	e.LatencySE = math.Sqrt(e.RTTStd * e.RTTStd / e.NEffReplied * (1 + k*k/2))
	return e
}
