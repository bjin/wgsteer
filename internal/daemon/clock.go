package daemon

import (
	"time"

	"golang.org/x/sys/unix"
)

// Clock is the loop's time source. Production uses CLOCK_BOOTTIME: it never
// steps (unlike the wall clock, which NTP steps at boot on RTC-less routers)
// and it advances during suspend, so the policy sees suspend/resume as a
// time gap (policy rule 7). Times from it are only compared with each
// other; WallTime converts them for display.
type Clock interface {
	Now() time.Time
}

type bootClock struct{}

func (bootClock) Now() time.Time {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		// CLOCK_BOOTTIME exists since Linux 2.6.39; fall back to the
		// monotonic reading rather than failing the loop.
		return time.Unix(0, 0).Add(time.Since(processStart))
	}
	return time.Unix(ts.Unix())
}

var processStart = time.Now()

// WallTime maps a loop-clock time to wall-clock time, using the current
// offset between the two clocks.
func WallTime(c Clock, t time.Time) time.Time {
	return time.Now().Add(t.Sub(c.Now())).Round(time.Millisecond)
}
