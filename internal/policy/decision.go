package policy

import (
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"time"

	"github.com/bjin/wgsteer/internal/stats"
)

// Kind is the rule that caused a switch.
type Kind string

// Switch kinds.
const (
	KindOutage  Kind = "outage"
	KindDegrade Kind = "degrade"
	KindRestore Kind = "restore"
	KindReload  Kind = "reload"
	KindStartup Kind = "startup"
)

// Blocker names the guard or condition that prevented a switch this tick.
type Blocker string

// Blockers. BlockerNone is used when the decision is a switch.
const (
	BlockerNone Blocker = ""
	// BlockerCooldown: a rule fired but the cooldown since the last switch
	// (or daemon start) has not elapsed.
	BlockerCooldown Blocker = "cooldown"
	// BlockerPersist: some candidate is significantly better, but the
	// degradation accumulator has not reached --persist.
	BlockerPersist Blocker = "persist"
	// BlockerRestoreHold: an earlier endpoint is not worse, but its revert
	// accumulator has not reached its (backed-off) hold.
	BlockerRestoreHold Blocker = "restore-hold"
	// BlockerNotFresh: a rule fired, but none of its targets is fresh.
	BlockerNotFresh Blocker = "not-fresh"
	// BlockerNothingBetter: no candidate is better beyond noise.
	BlockerNothingBetter Blocker = "nothing-better"
	// BlockerAllDown: no endpoint, active included, is fresh.
	BlockerAllDown Blocker = "all-down"
	// BlockerWarmingUp: the active endpoint (or, without one, every
	// candidate) has fewer than --min-samples valid samples.
	BlockerWarmingUp Blocker = "warming-up"
	// BlockerNoCandidate: no other endpoint is eligible (single-entry list,
	// or all others are down while the active one works).
	BlockerNoCandidate Blocker = "no-candidate"
	// BlockerOutageUnconfirmed: the active's loss run reached K, but its
	// newest loss predates the outage target's current run of replies (e.g.
	// all paths recovered after an all-down episode and the target was
	// re-probed first); the rule waits for the active's next probe.
	BlockerOutageUnconfirmed Blocker = "outage-unconfirmed"
)

// Rule names used in RuleState.
const (
	RuleOutage  = "outage"
	RuleDegrade = "degrade"
	RuleRestore = "restore"
	RuleStartup = "startup"
	RuleReload  = "reload"
)

// Decision is the result of one Tick. A switch is only a proposal until the
// caller executes it and calls Engine.Commit.
type Decision struct {
	Switch bool           `json:"switch"`
	Kind   Kind           `json:"kind,omitempty"`
	From   netip.AddrPort `json:"from,omitzero"`
	To     netip.AddrPort `json:"to,omitzero"`
	// Blocker is the guard that prevented a switch (empty on a switch).
	Blocker Blocker `json:"blocker,omitempty"`
	// Reason is one explicit sentence: why the switch, or why no switch.
	Reason string `json:"reason"`
	// Record is the full decision record (the per-tick trace).
	Record Record `json:"record"`
}

// Record is the complete state the decision was based on.
type Record struct {
	At time.Time `json:"at"`
	// Active is the selected endpoint (zero if none).
	Active netip.AddrPort `json:"active,omitzero"`
	// Removed is a selection removed by a list reload, until the next switch.
	Removed netip.AddrPort `json:"removed,omitzero"`
	// Gap reports a time discontinuity this tick (accumulators and loss
	// runs were reset).
	Gap bool `json:"gap,omitempty"`
	// CooldownLeft is the remaining cooldown (JSON: nanoseconds).
	CooldownLeft time.Duration  `json:"cooldown_left"`
	Endpoints    []EndpointView `json:"endpoints"`
	Rules        []RuleState    `json:"rules"`
}

// EndpointView is one endpoint's estimate and rule inputs. Latency values are
// milliseconds; Cost is the unbiased cost (latency term × loss factor) and
// BiasedCost includes the order bias (1+β·Index).
type EndpointView struct {
	Addr      netip.AddrPort `json:"addr"`
	Index     int            `json:"index"`
	Active    bool           `json:"active"`
	Samples   int            `json:"samples"`
	Replies   int            `json:"replies"`
	Invalid   int            `json:"invalid"`
	Loss      Float          `json:"loss"`
	LossSE    Float          `json:"loss_se"`
	RTTMean   Float          `json:"rtt_mean"`
	RTTStd    Float          `json:"rtt_std"`
	Latency   Float          `json:"latency"`
	LatencySE Float          `json:"latency_se"`
	// LossFactor is 1 + α·p̂/(1−p̂).
	LossFactor Float `json:"loss_factor"`
	Cost       Float `json:"cost"`
	BiasedCost Float `json:"biased_cost"`
	Eligible   bool  `json:"eligible"`
	Fresh      bool  `json:"fresh"`
	// Gate is G(active→this); nil for the active endpoint or without one.
	Gate *Gated `json:"gate,omitempty"`
	// TrailingLosses is the loss run counted by the outage rule: it restarts
	// on a time gap and excludes losses from ticks where no endpoint was
	// fresh (common-mode outage).
	TrailingLosses int `json:"trailing_losses"`
	// RestoreLevel is the revert backoff level (hold = WTR·2^level).
	RestoreLevel int           `json:"restore_level"`
	Last         *stats.Sample `json:"last,omitempty"`
	LastInvalid  time.Time     `json:"last_invalid,omitzero"`
}

// Gated is the noise-gated comparison G(A→B): R* = ln(X_A/X_B),
// S* = √(SE(ln X_A)² + SE(ln X_B)²), R*Gated = sign(R)·max(0, |R|−c·S), and
// G = exp(RLatGated + RLossGated)·Bias with Bias = (1+β·i_A)/(1+β·i_B).
// When only A has no replies, G and the latency ratio are +Inf; when B has
// none, G is 0 and the latency ratio −Inf.
type Gated struct {
	G          Float `json:"g"`
	RLat       Float `json:"r_lat"`
	SLat       Float `json:"s_lat"`
	RLatGated  Float `json:"r_lat_gated"`
	RLoss      Float `json:"r_loss"`
	SLoss      Float `json:"s_loss"`
	RLossGated Float `json:"r_loss_gated"`
	Bias       Float `json:"bias"`
}

// RuleState is one rule's progress. Value and Hold are net-time accumulator
// and threshold (JSON: nanoseconds); Run and K the outage loss run and its
// adaptive threshold; Level the restore backoff level.
type RuleState struct {
	Rule   string         `json:"rule"`
	Target netip.AddrPort `json:"target,omitzero"`
	Value  time.Duration  `json:"value,omitempty"`
	Hold   time.Duration  `json:"hold,omitempty"`
	Level  int            `json:"level,omitempty"`
	K      int            `json:"k,omitempty"`
	Run    int            `json:"run,omitempty"`
	// Active reports that the rule's condition holds this tick.
	Active bool `json:"active"`
	// Fired reports that the rule reached its threshold this tick.
	Fired bool `json:"fired"`
}

// Float is a float64 whose JSON form is a number when finite and one of the
// strings "+Inf", "-Inf" or "NaN" otherwise (encoding/json rejects non-finite
// numbers). Infinite costs mean "no replies in the window".
type Float float64

// MarshalJSON implements json.Marshaler.
func (f Float) MarshalJSON() ([]byte, error) {
	v := float64(f)
	switch {
	case math.IsInf(v, 1):
		return []byte(`"+Inf"`), nil
	case math.IsInf(v, -1):
		return []byte(`"-Inf"`), nil
	case math.IsNaN(v):
		return []byte(`"NaN"`), nil
	}
	return json.Marshal(v)
}

// UnmarshalJSON implements json.Unmarshaler.
func (f *Float) UnmarshalJSON(b []byte) error {
	switch string(b) {
	case `"+Inf"`:
		*f = Float(math.Inf(1))
		return nil
	case `"-Inf"`:
		*f = Float(math.Inf(-1))
		return nil
	case `"NaN"`:
		*f = Float(math.NaN())
		return nil
	}
	var v float64
	if err := json.Unmarshal(b, &v); err != nil {
		return fmt.Errorf("policy float: %w", err)
	}
	*f = Float(v)
	return nil
}
