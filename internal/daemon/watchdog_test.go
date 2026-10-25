package daemon

import (
	"io"
	"log/slog"
	"testing"
	"time"
)

type fakeMono struct{ t time.Time }

func (f *fakeMono) now() time.Time { return f.t }

func newTestWatchdog(clock *fakeMono, exitCode *int) *Watchdog {
	*exitCode = -1
	return &Watchdog{
		Heartbeat: NewHeartbeat(clock.t),
		Limit:     15 * time.Second,
		Now:       clock.now,
		Exit:      func(code int) { *exitCode = code },
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func TestWatchdogFiresOnStall(t *testing.T) {
	clock := &fakeMono{t: time.Unix(1000, 0)}
	var code int
	w := newTestWatchdog(clock, &code)
	w.Heartbeat.Beat(clock.t)

	clock.t = clock.t.Add(15 * time.Second)
	if w.Check() || code != -1 {
		t.Fatal("heartbeat exactly at the limit must not fire")
	}
	clock.t = clock.t.Add(time.Millisecond)
	if !w.Check() || code == -1 || code == 0 {
		t.Fatalf("stalled loop: fired=%v code=%d, want non-zero exit", code != -1, code)
	}
}

func TestWatchdogSlowButAliveLoop(t *testing.T) {
	clock := &fakeMono{t: time.Unix(1000, 0)}
	var code int
	w := newTestWatchdog(clock, &code)
	// Each tick takes 10 s (slow), but the loop keeps beating.
	for i := range 100 {
		clock.t = clock.t.Add(10 * time.Second)
		w.Heartbeat.Beat(clock.t)
		clock.t = clock.t.Add(4 * time.Second)
		if w.Check() {
			t.Fatalf("tick %d: slow but alive loop triggered the watchdog", i)
		}
	}
	if code != -1 {
		t.Fatalf("exit called with %d", code)
	}
}

// The loop may be stalled writing to a blocked stderr; the watchdog shares
// that writer and must exit anyway.
func TestWatchdogExitsDespiteBlockedLog(t *testing.T) {
	r, blocked := io.Pipe() // nobody reads: every write blocks
	t.Cleanup(func() { r.Close() })
	clock := &fakeMono{t: time.Unix(1000, 0)}
	exited := make(chan int, 1)
	w := &Watchdog{
		Heartbeat:  NewHeartbeat(clock.t),
		Limit:      time.Second,
		Now:        clock.now,
		Exit:       func(code int) { exited <- code },
		Logger:     slog.New(slog.NewTextHandler(blocked, nil)),
		LogTimeout: 20 * time.Millisecond,
	}
	clock.t = clock.t.Add(2 * time.Second)
	go w.Check()
	select {
	case code := <-exited:
		if code == 0 {
			t.Fatal("watchdog exited with 0")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watchdog blocked on its log record instead of exiting")
	}
}
