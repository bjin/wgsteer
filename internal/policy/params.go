// Package policy scores endpoints and decides when to switch. It
// is pure: all time comes from the caller, so it is deterministic and
// testable with a fake clock.
package policy

import (
	"errors"
	"fmt"
	"time"
)

// Fixed constants of the decision rules.
const (
	// MaxRestoreLevel caps the restore backoff: hold = WaitToRestore·2^level.
	MaxRestoreLevel = 3
	// RestoreLevelDecay is how long without a degradation exit from an
	// endpoint lowers its restore level by one.
	RestoreLevelDecay = time.Hour
	// GapFactor: a tick more than GapFactor·Interval after the previous one
	// is a time discontinuity (suspend/resume) and resets accumulators and
	// loss runs.
	GapFactor = 10
	// OutageMinK and OutageMaxK clamp the adaptive outage run length.
	OutageMinK = 3
	OutageMaxK = 10
	// OutageStartupSamples is the minimum history of a fresh outage target
	// when no fresh candidate is eligible yet (startup, freshly added).
	OutageStartupSamples = 2
)

// Params are the policy tunables. Field names follow the CLI flags.
type Params struct {
	// Interval is one probe slot (--probe-interval).
	Interval time.Duration
	// Persist is the net time degradation must hold (--persist).
	Persist time.Duration
	// Cooldown is the minimum time between switches of any kind, also
	// measured from daemon start (--cooldown).
	Cooldown time.Duration
	// WaitToRestore is the base net time an earlier endpoint must stay
	// "not worse" before reverting to it; 0 disables revert.
	WaitToRestore time.Duration
	// MarginAbs is the minimum absolute effect, in cost milliseconds.
	MarginAbs time.Duration
	// History is the ring size per endpoint (--history).
	History int
	// MinSamples is the number of valid samples for eligibility.
	MinSamples int
	// HalfLife is the recency half-life in samples of an endpoint.
	HalfLife float64
	// NoiseGate is c, the per-component gate in standard errors.
	NoiseGate float64
	// LossWeight is α, JitterWeight k and OrderBias β of the cost model.
	LossWeight   float64
	JitterWeight float64
	OrderBias    float64
	// Margin is the minimum relative effect for "significantly worse".
	Margin float64
	// OutageEpsilon is ε of the adaptive outage run length.
	OutageEpsilon float64
}

// DefaultParams returns the tuned defaults. They meet the calibration table
// and the behavioral targets of the package tests, and were chosen on a 72 h
// router dry-run replayed with tools/tune.py (10 endpoints and subsets of 4
// and 6), with those targets as a constraint:
//
//   - HalfLife 60, History 267 (n_eff ≈ 158): enough samples for the loss
//     component to pass the gate in S5 (20% vs 3% loss, +30 ms); longer
//     half-lives react too slowly to faults on the active endpoint.
//   - LossWeight 7, NoiseGate 2.5: loss-driven switches for clear loss
//     differences while switches between equal paths stay rare; lower gates
//     switch on noise between equal 5%-loss paths.
//   - JitterWeight 2.5: a latency tail (30% of replies +100 ms) is caught
//     within the same few minutes as a mean shift.
//   - Margin 0.14 with WaitToRestore 45m: an earlier endpoint is restored
//     only after 45 min of net time not worse, so a daily jitter episode on
//     it does not pull the selection back early; the lower margin lets the
//     selection leave it again when it degrades against the order bias.
//   - Persist 30s: detection speed of latency steps.
func DefaultParams() Params {
	return Params{
		Interval:      time.Second,
		Persist:       30 * time.Second,
		Cooldown:      30 * time.Second,
		WaitToRestore: 45 * time.Minute,
		MarginAbs:     10 * time.Millisecond,
		History:       267,
		MinSamples:    20,
		HalfLife:      60,
		NoiseGate:     2.5,
		LossWeight:    7,
		JitterWeight:  2.5,
		OrderBias:     0.02,
		Margin:        0.14,
		OutageEpsilon: 1e-5,
	}
}

// Validate checks ranges and cross-field constraints.
func (p Params) Validate() error {
	var errs []error
	check := func(ok bool, format string, args ...any) {
		if !ok {
			errs = append(errs, fmt.Errorf(format, args...))
		}
	}
	check(p.Interval > 0, "probe interval must be positive, got %v", p.Interval)
	check(p.Persist >= 0, "persist must not be negative, got %v", p.Persist)
	check(p.Cooldown >= 0, "cooldown must not be negative, got %v", p.Cooldown)
	check(p.WaitToRestore >= 0, "wait-to-restore must not be negative, got %v", p.WaitToRestore)
	check(p.MarginAbs >= 0, "margin-abs must not be negative, got %v", p.MarginAbs)
	check(p.History >= 2, "history must be at least 2, got %d", p.History)
	check(p.MinSamples >= 1 && p.MinSamples <= p.History,
		"min-samples must be in [1, history=%d], got %d", p.History, p.MinSamples)
	check(p.HalfLife > 0, "half-life must be positive, got %g", p.HalfLife)
	check(p.NoiseGate >= 0, "noise-gate must not be negative, got %g", p.NoiseGate)
	check(p.LossWeight >= 0, "loss-weight must not be negative, got %g", p.LossWeight)
	check(p.JitterWeight >= 0, "jitter-weight must not be negative, got %g", p.JitterWeight)
	check(p.OrderBias >= 0, "order-bias must not be negative, got %g", p.OrderBias)
	check(p.Margin >= 0, "margin must not be negative, got %g", p.Margin)
	check(p.OutageEpsilon > 0 && p.OutageEpsilon < 1, "outage-epsilon must be in (0, 1), got %g", p.OutageEpsilon)
	return errors.Join(errs...)
}
