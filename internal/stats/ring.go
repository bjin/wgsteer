// Package stats holds per-endpoint probe history and the recency-weighted
// estimator of loss and latency.
package stats

import "time"

// Sample is one valid probe result. Invalid probes (sent without a usable
// session) are never stored in a Ring.
type Sample struct {
	// At is when the probe was sent.
	At time.Time `json:"at"`
	// Replied is false for a loss, including replies later than the timeout.
	Replied bool `json:"replied"`
	// RTT is the round-trip time of a reply; zero for a loss. JSON: nanoseconds.
	RTT time.Duration `json:"rtt"`
}

// Ring keeps the last Cap() valid samples of one endpoint. Index 0 is the
// newest sample.
type Ring struct {
	buf  []Sample
	head int // index of the next write
	n    int
}

// NewRing returns an empty ring holding up to capacity samples (minimum 1).
func NewRing(capacity int) *Ring {
	if capacity < 1 {
		capacity = 1
	}
	return &Ring{buf: make([]Sample, capacity)}
}

// Add appends s as the newest sample, evicting the oldest when full.
func (r *Ring) Add(s Sample) {
	r.buf[r.head] = s
	r.head++
	if r.head == len(r.buf) {
		r.head = 0
	}
	if r.n < len(r.buf) {
		r.n++
	}
}

// Len returns the number of stored samples.
func (r *Ring) Len() int { return r.n }

// Cap returns the capacity.
func (r *Ring) Cap() int { return len(r.buf) }

// At returns the i-th newest sample (0 = newest). It panics if i is out of
// range.
func (r *Ring) At(i int) Sample {
	if i < 0 || i >= r.n {
		panic("stats: ring index out of range")
	}
	j := r.head - 1 - i
	if j < 0 {
		j += len(r.buf)
	}
	return r.buf[j]
}

// Last returns the newest sample, if any.
func (r *Ring) Last() (Sample, bool) {
	if r.n == 0 {
		return Sample{}, false
	}
	return r.At(0), true
}

// TrailingLosses counts consecutive losses ending at the newest sample.
func (r *Ring) TrailingLosses() int {
	k := 0
	for k < r.n && !r.At(k).Replied {
		k++
	}
	return k
}

// Reset drops all samples.
func (r *Ring) Reset() {
	r.head, r.n = 0, 0
}
