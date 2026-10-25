package daemon

import (
	"context"
	"io"
	"log/slog"
)

// Logging owns the runtime-adjustable log level (SIGUSR2 toggles
// between the configured level and debug).
type Logging struct {
	Logger     *slog.Logger
	level      slog.LevelVar
	configured slog.Level
}

// NewLogging creates a text logger on w. slog's text handler prints
// millisecond timestamps, which switch timing analysis needs (logd only
// keeps seconds).
func NewLogging(w io.Writer, configured slog.Level) *Logging {
	l := &Logging{configured: configured}
	l.level.Set(configured)
	l.Logger = slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: &l.level}))
	return l
}

// ToggleDebug switches between the configured level and debug, logs the
// new level, and returns it.
func (l *Logging) ToggleDebug() slog.Level {
	next := slog.LevelDebug
	if l.level.Level() == slog.LevelDebug {
		next = l.configured
	}
	l.level.Set(next)
	// Log at a severity visible both in debug and at the configured level.
	l.Logger.Log(context.Background(), max(slog.LevelInfo, l.configured), "log level changed", "level", next.String())
	return next
}

// Debug reports whether debug records are currently enabled.
func (l *Logging) Debug() bool {
	return l.level.Level() <= slog.LevelDebug
}
