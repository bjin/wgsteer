package daemon

import (
	"context"
	"log/slog"
	"runtime"
	"sync/atomic"
	"time"
)

// Heartbeat is stamped by the event loop on every tick and read by the
// watchdog goroutine. It stores a monotonic offset, so suspend (which stops
// CLOCK_MONOTONIC) does not look like a stall after resume.
type Heartbeat struct {
	base time.Time
	last atomic.Int64 // nanoseconds since base
}

// NewHeartbeat returns a heartbeat stamped at now.
func NewHeartbeat(now time.Time) *Heartbeat {
	h := &Heartbeat{base: now}
	return h
}

// Beat records that the loop is alive at now.
func (h *Heartbeat) Beat(now time.Time) {
	h.last.Store(int64(now.Sub(h.base)))
}

// Age returns how long ago the last beat happened.
func (h *Heartbeat) Age(now time.Time) time.Duration {
	return now.Sub(h.base) - time.Duration(h.last.Load())
}

// Watchdog exits the process when the loop's heartbeat is older than Limit
// (docs/design.md, Lifecycle). Exiting closes the nftables owner socket, so
// the kernel removes the table and the service manager respawns the daemon.
type Watchdog struct {
	Heartbeat *Heartbeat
	Limit     time.Duration
	Now       func() time.Time // monotonic time source; time.Now in production
	Exit      func(code int)   // os.Exit in production
	Logger    *slog.Logger
	// LogTimeout bounds the wait for the stall report (default 1 s). The loop
	// may be stalled writing to the same blocked stderr, so the exit never
	// depends on the report getting out.
	LogTimeout time.Duration
}

// Check fires the exit path if the loop stalled. It reports whether it did.
func (w *Watchdog) Check() bool {
	age := w.Heartbeat.Age(w.Now())
	if age <= w.Limit {
		return false
	}
	logged := make(chan struct{})
	go func() {
		defer close(logged)
		buf := make([]byte, 1<<20)
		buf = buf[:runtime.Stack(buf, true)]
		w.Logger.Error("watchdog: event loop stalled, exiting",
			"stalled_for", age.Round(time.Millisecond), "limit", w.Limit, "stacks", string(buf))
	}()
	timeout := w.LogTimeout
	if timeout <= 0 {
		timeout = time.Second
	}
	select {
	case <-logged:
	case <-time.After(timeout):
	}
	w.Exit(3)
	return true
}

// Run checks the heartbeat several times per Limit until ctx ends.
func (w *Watchdog) Run(ctx context.Context) {
	t := time.NewTicker(max(w.Limit/4, 10*time.Millisecond))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if w.Check() {
				return
			}
		}
	}
}
