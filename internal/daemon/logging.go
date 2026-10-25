package daemon

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"time"

	"github.com/bjin/wgsteer/internal/logfile"
)

// Logging owns the runtime-adjustable log level (SIGUSR2 toggles
// between the configured level and debug) and, with --log-dir, the log
// file writer.
type Logging struct {
	Logger     *slog.Logger
	level      slog.LevelVar
	configured slog.Level
	file       *logfile.Writer // nil: logging to a plain writer (stderr)
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

// OpenLogging creates the logger for cfg: on stderr without --log-dir,
// otherwise into hourly gzip files in cfg.LogDir (package logfile), with
// only the file writer's failure notices on stderr. Every file opened by a
// rotation starts with the startup "config" record, so each file states the
// effective settings. Call Close before exiting.
func OpenLogging(cfg Config, stderr io.Writer) *Logging {
	if cfg.LogDir == "" {
		return NewLogging(stderr, cfg.LogLevel)
	}
	l := &Logging{configured: cfg.LogLevel}
	l.level.Set(cfg.LogLevel)
	attrs := cfg.attrs()
	l.file = logfile.New(cfg.LogDir, cfg.LogMaxAge, func(now time.Time) []byte { return l.configRecord(now, attrs) }, stderr)
	l.Logger = slog.New(slog.NewTextHandler(l.file, &slog.HandlerOptions{Level: &l.level}))
	return l
}

// configRecord formats the "config" record exactly like the startup report,
// or nothing when info records are disabled. It formats into a buffer: it
// runs inside the file writer, which must not be written to recursively.
func (l *Logging) configRecord(now time.Time, attrs []any) []byte {
	if l.level.Level() > slog.LevelInfo {
		return nil
	}
	var b bytes.Buffer
	r := slog.NewRecord(now, slog.LevelInfo, "config", 0)
	r.Add(attrs...)
	if err := slog.NewTextHandler(&b, nil).Handle(context.Background(), r); err != nil {
		return nil
	}
	return b.Bytes()
}

// Close finishes the log file (gzip trailer). Later records are dropped.
// It is a no-op when logging to stderr.
func (l *Logging) Close() {
	if l.file != nil {
		l.file.Close()
	}
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
