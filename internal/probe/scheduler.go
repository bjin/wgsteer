package probe

import (
	"math/rand/v2"
	"net/netip"
	"time"

	"github.com/bjin/wgsteer/internal/endpoints"
)

const (
	// RejectAfterTime is WireGuard's REJECT_AFTER_TIME: a keypair older than
	// this is unusable for sending and receiving.
	RejectAfterTime = 180 * time.Second

	// SessionMargin is subtracted from RejectAfterTime for SessionValid. It
	// covers the probe's own in-flight time (the reply must be decrypted with
	// the same keypair, at most --probe-timeout < --probe-interval later),
	// the gap between the IpcGet that read last_handshake_time and the send,
	// and wall-clock granularity, with ample headroom for intervals of a few
	// seconds.
	SessionMargin = 10 * time.Second
)

// SessionValid reports whether a probe sent at now has a usable session:
// a handshake completed less than RejectAfterTime-SessionMargin ago. A zero
// lastHandshake (never) is invalid. A handshake time in the future (wall
// clock stepped back) counts as valid: wireguard-go's own timers are
// monotonic and rekey on schedule, which refreshes the time.
func SessionValid(lastHandshake, now time.Time) bool {
	if lastHandshake.IsZero() {
		return false
	}
	return now.Sub(lastHandshake) < RejectAfterTime-SessionMargin
}

// Slot is one probe slot: the endpoint probed and the identifiers of its
// single echo request.
type Slot struct {
	Endpoint   netip.AddrPort
	Index      int // position of Endpoint in the list passed to Begin
	Seq        uint16
	Nonce      uint64
	EndpointID uint32
	Start      time.Time // the now passed to Begin
	Deadline   time.Time // Start + timeout
	Valid      bool      // the probe had a usable session at Start
}

// Result is the sample produced by a finished slot.
type Result struct {
	Endpoint netip.AddrPort
	Seq      uint16
	At       time.Time // the slot's Start
	Valid    bool      // false: excluded from statistics, never a loss
	Replied  bool      // false with Valid: a loss
	RTT      time.Duration
}

// Scheduler picks endpoints in strict round-robin and attributes replies to
// the single pending slot. It is pure (time is injected) and is owned by
// one goroutine.
type Scheduler struct {
	timeout time.Duration
	rng     rand.Source
	seq     uint16

	last   netip.AddrPort // endpoint of the previous slot
	cursor int            // its index; the next start position if it leaves the list

	pending bool
	slot    Slot
	replied bool
	rtt     time.Duration
}

// NewScheduler returns a scheduler that accepts replies with RTT <= timeout.
// rng supplies nonces and the initial sequence number; nil uses the
// randomly seeded global source.
func NewScheduler(timeout time.Duration, rng rand.Source) *Scheduler {
	if rng == nil {
		rng = globalSource{}
	}
	return &Scheduler{timeout: timeout, rng: rng, seq: uint16(rng.Uint64())}
}

type globalSource struct{}

func (globalSource) Uint64() uint64 { return rand.Uint64() }

// Begin opens the next slot and registers it as the single pending probe.
// It walks list in strict round-robin, continuing after the previously
// probed endpoint. When the list changes (reload) and that endpoint is gone,
// it continues at the endpoint that took its position. An unfinished
// previous slot is discarded without a sample. An empty list returns a zero
// Slot (invalid Endpoint) and leaves nothing pending.
func (s *Scheduler) Begin(list []netip.AddrPort, now time.Time, valid bool) Slot {
	s.pending = false
	if len(list) == 0 {
		return Slot{}
	}
	var i int
	if j := endpoints.Index(list, s.last); s.last.IsValid() && j >= 0 {
		i = (j + 1) % len(list)
	} else {
		i = s.cursor % len(list)
	}
	ep := list[i]
	s.last, s.cursor = ep, i
	s.seq++
	s.slot = Slot{
		Endpoint:   ep,
		Index:      i,
		Seq:        s.seq,
		Nonce:      s.rng.Uint64(),
		EndpointID: endpointID(ep),
		Start:      now,
		Deadline:   now.Add(s.timeout),
		Valid:      valid,
	}
	s.pending, s.replied, s.rtt = true, false, 0
	return s.slot
}

// Pending returns the open slot, if any.
func (s *Scheduler) Pending() (Slot, bool) { return s.slot, s.pending }

// Match records r for the pending slot. It returns true only for the first
// reply whose seq, nonce and endpoint id match the pending slot and whose
// RTT is within the timeout. Replies for finished slots never match.
func (s *Scheduler) Match(r Reply) bool {
	if !s.pending || s.replied {
		return false
	}
	if r.Seq != s.slot.Seq || r.Nonce != s.slot.Nonce || r.EndpointID != s.slot.EndpointID {
		return false
	}
	rtt := r.RTT()
	if rtt < 0 || rtt > s.timeout {
		return false
	}
	s.replied, s.rtt = true, rtt
	return true
}

// Finish closes the pending slot and returns its sample; false if no slot
// is pending.
func (s *Scheduler) Finish() (Result, bool) {
	if !s.pending {
		return Result{}, false
	}
	s.pending = false
	return Result{
		Endpoint: s.slot.Endpoint,
		Seq:      s.slot.Seq,
		At:       s.slot.Start,
		Valid:    s.slot.Valid,
		Replied:  s.replied,
		RTT:      s.rtt,
	}, true
}

// endpointID is a stable 32-bit id of an endpoint (FNV-1a over the 16-byte
// address and the big-endian port), carried in the payload.
func endpointID(ep netip.AddrPort) uint32 {
	const offset32, prime32 = 2166136261, 16777619
	h := uint32(offset32)
	for _, b := range ep.Addr().As16() {
		h = (h ^ uint32(b)) * prime32
	}
	h = (h ^ uint32(ep.Port()>>8)) * prime32
	return (h ^ uint32(ep.Port()&0xff)) * prime32
}
