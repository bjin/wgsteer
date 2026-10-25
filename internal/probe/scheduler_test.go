package probe

import (
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"
	"time"
)

var (
	epA = netip.MustParseAddrPort("192.0.2.1:51820")
	epB = netip.MustParseAddrPort("192.0.2.2:51820")
	epC = netip.MustParseAddrPort("[2001:db8::3]:443")
	epD = netip.MustParseAddrPort("198.51.100.4:9")
)

const testTimeout = 500 * time.Millisecond

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func newTestScheduler() *Scheduler {
	return NewScheduler(testTimeout, rand.NewPCG(1, 2))
}

// replyFor is the reply to slot's echo with the given RTT.
func replyFor(s Slot, rtt time.Duration) Reply {
	return Reply{Seq: s.Seq, Nonce: s.Nonce, EndpointID: s.EndpointID, SentAt: time.Second, RecvAt: time.Second + rtt}
}

// order runs n slots over list and returns the probed endpoints.
func order(s *Scheduler, list []netip.AddrPort, n int) []netip.AddrPort {
	var got []netip.AddrPort
	for i := range n {
		slot := s.Begin(list, t0.Add(time.Duration(i)*time.Second), true)
		got = append(got, slot.Endpoint)
		if list[slot.Index] != slot.Endpoint {
			panic("Index does not match Endpoint")
		}
		s.Finish()
	}
	return got
}

func TestSchedulerRoundRobin(t *testing.T) {
	s := newTestScheduler()
	list := []netip.AddrPort{epA, epB, epC}
	want := []netip.AddrPort{epA, epB, epC, epA, epB, epC, epA}
	if got := order(s, list, 7); !slices.Equal(got, want) {
		t.Errorf("order %v, want %v", got, want)
	}
}

func TestSchedulerReload(t *testing.T) {
	for _, tc := range []struct {
		name     string
		before   int // slots on [A B C] before the reload
		reloaded []netip.AddrPort
		want     []netip.AddrPort
	}{
		// last probed B is still listed (moved): continue after it.
		{"last kept", 2, []netip.AddrPort{epB, epD, epA}, []netip.AddrPort{epD, epA, epB}},
		// last probed B removed: continue with what took its position.
		{"last removed", 2, []netip.AddrPort{epA, epC, epD}, []netip.AddrPort{epC, epD, epA}},
		// last probed C (at the end) removed from a shorter list: wrap.
		{"last removed at end", 3, []netip.AddrPort{epA, epB}, []netip.AddrPort{epA, epB, epA}},
		// an endpoint inserted after the last probed one comes next.
		{"new endpoint added", 1, []netip.AddrPort{epA, epD, epB, epC}, []netip.AddrPort{epD, epB, epC, epA}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestScheduler()
			order(s, []netip.AddrPort{epA, epB, epC}, tc.before)
			if got := order(s, tc.reloaded, len(tc.want)); !slices.Equal(got, tc.want) {
				t.Errorf("after reload %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSchedulerEmptyList(t *testing.T) {
	s := newTestScheduler()
	if slot := s.Begin(nil, t0, true); slot.Endpoint.IsValid() {
		t.Errorf("slot for empty list: %+v", slot)
	}
	if _, ok := s.Finish(); ok {
		t.Error("empty list left a pending slot")
	}
}

func TestSchedulerSlotIdentifiers(t *testing.T) {
	s := newTestScheduler()
	list := []netip.AddrPort{epA, epB}
	a := s.Begin(list, t0, true)
	s.Finish()
	b := s.Begin(list, t0.Add(time.Second), false)
	s.Finish()
	a2 := s.Begin(list, t0.Add(2*time.Second), true)
	if b.Seq != a.Seq+1 || a2.Seq != b.Seq+1 {
		t.Errorf("seq not incrementing: %d %d %d", a.Seq, b.Seq, a2.Seq)
	}
	if a.Nonce == b.Nonce || a.Nonce == a2.Nonce {
		t.Errorf("nonces repeat")
	}
	if a.EndpointID != a2.EndpointID || a.EndpointID == b.EndpointID {
		t.Errorf("endpoint ids not stable per endpoint: %x %x %x", a.EndpointID, b.EndpointID, a2.EndpointID)
	}
	if !a2.Deadline.Equal(a2.Start.Add(testTimeout)) || !a2.Start.Equal(t0.Add(2*time.Second)) || b.Valid {
		t.Errorf("slot times/validity: %+v %+v", a2, b)
	}
}

func TestSchedulerMatch(t *testing.T) {
	list := []netip.AddrPort{epA, epB}
	for _, tc := range []struct {
		name    string
		mutate  func(*Reply)
		rtt     time.Duration
		replied bool
	}{
		{"match", nil, 20 * time.Millisecond, true},
		{"rtt equal to timeout", nil, testTimeout, true},
		{"rtt beyond timeout is loss", nil, testTimeout + time.Microsecond, false},
		{"negative rtt", nil, -time.Millisecond, false},
		{"wrong seq", func(r *Reply) { r.Seq++ }, time.Millisecond, false},
		{"wrong nonce", func(r *Reply) { r.Nonce ^= 1 }, time.Millisecond, false},
		{"wrong endpoint id", func(r *Reply) { r.EndpointID ^= 1 }, time.Millisecond, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestScheduler()
			slot := s.Begin(list, t0, true)
			r := replyFor(slot, tc.rtt)
			if tc.mutate != nil {
				tc.mutate(&r)
			}
			if got := s.Match(r); got != tc.replied {
				t.Errorf("Match = %v, want %v", got, tc.replied)
			}
			res, ok := s.Finish()
			if !ok {
				t.Fatal("no pending slot")
			}
			want := Result{Endpoint: epA, Seq: slot.Seq, At: t0, Valid: true, Replied: tc.replied}
			if tc.replied {
				want.RTT = tc.rtt
			}
			if res != want {
				t.Errorf("result %+v, want %+v", res, want)
			}
		})
	}
}

func TestSchedulerDuplicateReplyKeepsFirst(t *testing.T) {
	s := newTestScheduler()
	slot := s.Begin([]netip.AddrPort{epA}, t0, true)
	if !s.Match(replyFor(slot, 10*time.Millisecond)) {
		t.Fatal("first reply not matched")
	}
	if s.Match(replyFor(slot, 20*time.Millisecond)) {
		t.Error("duplicate reply matched")
	}
	if res, _ := s.Finish(); res.RTT != 10*time.Millisecond {
		t.Errorf("RTT %v, want the first reply's", res.RTT)
	}
}

func TestSchedulerLateReplyStaysLoss(t *testing.T) {
	s := newTestScheduler()
	list := []netip.AddrPort{epA, epB}
	a := s.Begin(list, t0, true)
	resA, _ := s.Finish()
	if resA.Replied || !resA.Valid {
		t.Fatalf("A: %+v, want a valid loss", resA)
	}
	// A's reply arrives during B's slot, even with an in-timeout RTT.
	b := s.Begin(list, t0.Add(time.Second), true)
	if s.Match(replyFor(a, 10*time.Millisecond)) {
		t.Error("late reply for A matched during B's slot")
	}
	resB, _ := s.Finish()
	if resB.Endpoint != epB || resB.Replied {
		t.Errorf("B: %+v, want a loss for B", resB)
	}
	// And after every slot is finished.
	if s.Match(replyFor(a, 10*time.Millisecond)) || s.Match(replyFor(b, 10*time.Millisecond)) {
		t.Error("reply matched with no pending slot")
	}
	if _, ok := s.Finish(); ok {
		t.Error("Finish twice")
	}
}

func TestSchedulerInvalidSlot(t *testing.T) {
	s := newTestScheduler()
	slot := s.Begin([]netip.AddrPort{epA}, t0, false)
	res, _ := s.Finish()
	if res.Valid || res.Replied {
		t.Errorf("unanswered invalid slot: %+v, want invalid (not a loss)", res)
	}
	slot = s.Begin([]netip.AddrPort{epA}, t0.Add(time.Second), false)
	s.Match(replyFor(slot, time.Millisecond))
	if res, _ := s.Finish(); res.Valid || !res.Replied {
		t.Errorf("answered invalid slot: %+v, want invalid", res)
	}
}

func TestSchedulerBeginDiscardsUnfinished(t *testing.T) {
	s := newTestScheduler()
	list := []netip.AddrPort{epA, epB}
	a := s.Begin(list, t0, true)
	b := s.Begin(list, t0.Add(time.Second), true)
	if s.Match(replyFor(a, time.Millisecond)) {
		t.Error("discarded slot matched")
	}
	if p, ok := s.Pending(); !ok || p != b {
		t.Errorf("pending %+v %v, want B", p, ok)
	}
	if res, _ := s.Finish(); res.Endpoint != epB {
		t.Errorf("finished %v, want B", res.Endpoint)
	}
}

func TestSessionValid(t *testing.T) {
	limit := RejectAfterTime - SessionMargin
	for _, tc := range []struct {
		name string
		hs   time.Time
		want bool
	}{
		{"never", time.Time{}, false},
		{"fresh", t0, true},
		{"just below limit", t0.Add(-limit + time.Nanosecond), true},
		{"at limit", t0.Add(-limit), false},
		{"expired", t0.Add(-RejectAfterTime), false},
		{"in the future", t0.Add(time.Minute), true},
	} {
		if got := SessionValid(tc.hs, t0); got != tc.want {
			t.Errorf("%s: SessionValid = %v, want %v", tc.name, got, tc.want)
		}
	}
	if limit <= 0 || limit >= RejectAfterTime {
		t.Errorf("margin leaves limit %v", limit)
	}
}
