// Package logfile writes the log to gzip files named after the UTC hour.
//
// Files are named wgsteer-YYYY-MM-DDTHH.log.gz after the UTC hour of the
// wall clock at write time. Every file is created new and holds one gzip
// member written by one Writer: a restart within the hour, a wall clock
// stepped back or a retry after a write failure creates the hour's next file,
// wgsteer-YYYY-MM-DDTHH_1.log.gz, _2, ... and never appends, because the
// previous writer may have been killed mid-block. The open member is
// sync-flushed once its unflushed data is FlushDelay old, so a reader that
// decompresses the unterminated stream sees every line older than that;
// rotation and Close finish the member.
package logfile

import (
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// FlushDelay is the longest time written data stays buffered in the
// compressor before a sync flush makes it readable.
const FlushDelay = 10 * time.Second

const (
	namePrefix = "wgsteer-"
	nameSuffix = ".log.gz"
	hourLayout = "2006-01-02T15"
)

// ErrClosed is returned by Write after Close.
var ErrClosed = errors.New("log file closed")

// errRetryLater is returned by Write while a failure episode waits to retry.
var errRetryLater = errors.New("log file unavailable, retrying")

// maxSeq bounds the files per hour (restarts within the hour, retries).
const maxSeq = 10000

// Name returns the file name for the UTC hour containing t: the first file
// of that hour. Later files of the same hour are NameSeq(t, 1), 2, ...
func Name(t time.Time) string {
	return NameSeq(t, 0)
}

// NameSeq returns the name of file seq of the UTC hour containing t:
// wgsteer-YYYY-MM-DDTHH.log.gz for seq 0, wgsteer-YYYY-MM-DDTHH_<seq>.log.gz
// after it. Readers order files by hour, then seq.
func NameSeq(t time.Time, seq int) string {
	hour := t.UTC().Format(hourLayout)
	if seq == 0 {
		return namePrefix + hour + nameSuffix
	}
	return namePrefix + hour + "_" + strconv.Itoa(seq) + nameSuffix
}

// parseName returns the hour and sequence number a file name stands for; ok
// is false unless name is exactly what NameSeq produces.
func parseName(name string) (hour time.Time, seq int, ok bool) {
	s, ok := strings.CutPrefix(name, namePrefix)
	if !ok {
		return time.Time{}, 0, false
	}
	if s, ok = strings.CutSuffix(s, nameSuffix); !ok {
		return time.Time{}, 0, false
	}
	if h, n, found := strings.Cut(s, "_"); found {
		var err error
		if seq, err = strconv.Atoi(n); err != nil || seq < 1 {
			return time.Time{}, 0, false
		}
		s = h
	}
	hour, err := time.Parse(hourLayout, s)
	if err != nil || NameSeq(hour, seq) != name {
		return time.Time{}, 0, false
	}
	return hour, seq, true
}

// Writer is an io.Writer for a slog handler: each Write is one record, and
// a record never spans two files. It is safe for concurrent use.
type Writer struct {
	dir    string
	maxAge time.Duration
	header func(now time.Time) []byte
	errOut io.Writer

	// Test hooks: the wall clock and the flush timer.
	now       func() time.Time
	afterFunc func(time.Duration, func())

	mu      sync.Mutex
	f       *os.File     // nil: no open member
	gz      *gzip.Writer // kept across files (Reset), allocated on first open
	hour    time.Time    // UTC hour of the last opened file; zero before the first
	path    string
	gen     uint64    // member generation; a stale flush timer does nothing
	pending bool      // unflushed data; a flush timer is armed for gen
	failing bool      // in a failure episode: notified once on errOut
	retryAt time.Time // in a failure episode with no open file: no new open before
	closed  bool
}

// New returns a Writer into dir that deletes files of hours ended more than
// maxAge ago. header, if not nil, is called whenever a later hour's file is
// opened (not for the first file) and its result starts that file; it runs
// with the Writer locked and must not write to it. Failure notices go to
// errOut. Nothing is opened until the first Write.
func New(dir string, maxAge time.Duration, header func(now time.Time) []byte, errOut io.Writer) *Writer {
	return &Writer{dir: dir, maxAge: maxAge, header: header, errOut: errOut,
		now: time.Now, afterFunc: func(d time.Duration, f func()) { time.AfterFunc(d, f) }}
}

// Write appends p to the current hour's file, rotating first if the hour
// changed. A failure is reported once per episode on errOut and dropped
// data is not retried; a Write at least FlushDelay later opens a new file
// (each attempt may create one, so they are spaced out).
func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, ErrClosed
	}
	if err := w.write(w.now(), p); err != nil {
		w.fail(err)
		return 0, err
	}
	if w.failing {
		w.failing = false
		fmt.Fprintf(w.errOut, "wgsteer: log file: writing again to %s\n", w.path)
	}
	return len(p), nil
}

func (w *Writer) write(now time.Time, p []byte) error {
	if hour := now.UTC().Truncate(time.Hour); w.f == nil || !hour.Equal(w.hour) {
		if w.f == nil && w.failing && now.Before(w.retryAt) {
			return errRetryLater
		}
		if err := w.open(now, hour); err != nil {
			w.retryAt = now.Add(FlushDelay)
			return err
		}
	}
	if _, err := w.gz.Write(p); err != nil {
		w.drop()
		w.retryAt = now.Add(FlushDelay)
		return fmt.Errorf("write %s: %w", w.path, err)
	}
	if !w.pending {
		w.pending = true
		gen := w.gen
		w.afterFunc(FlushDelay, func() { w.flush(gen) })
	}
	return nil
}

// open finishes the open member and creates the hour's next unused file:
// never an existing one. A member left without its trailer (a killed or
// failed writer) may end mid-block, and anything written behind it would be
// undecodable, so every file holds exactly one member of one writer.
func (w *Writer) open(now, hour time.Time) error {
	if w.f != nil {
		if err := w.finish(); err != nil {
			w.fail(err)
		}
	}
	if err := os.MkdirAll(w.dir, 0o750); err != nil {
		return fmt.Errorf("create log dir: %w", err)
	}
	var (
		name, path string
		f          *os.File
		err        error
	)
	for seq := 0; ; seq++ {
		if seq == maxSeq {
			return fmt.Errorf("create log file: %d files for %s already exist", maxSeq, Name(hour))
		}
		name = NameSeq(hour, seq)
		path = filepath.Join(w.dir, name)
		f, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
		if !errors.Is(err, fs.ErrExist) {
			break
		}
	}
	if err != nil {
		return err
	}
	first, rotation := w.hour.IsZero(), !w.hour.IsZero() && !hour.Equal(w.hour)
	if w.gz == nil {
		w.gz = gzip.NewWriter(f)
	} else {
		w.gz.Reset(f)
	}
	w.f, w.hour, w.path = f, hour, path
	w.gen++
	w.pending = false
	if first || rotation {
		w.prune(now, name)
	}
	if rotation && w.header != nil {
		if h := w.header(now); len(h) > 0 {
			if _, err := w.gz.Write(h); err != nil {
				w.drop()
				return fmt.Errorf("write %s: %w", path, err)
			}
		}
	}
	return nil
}

// finish writes the member's trailer and closes the file.
func (w *Writer) finish() error {
	err := w.gz.Close()
	if cerr := w.f.Close(); err == nil {
		err = cerr
	}
	w.f = nil
	w.gen++
	w.pending = false
	if err != nil {
		return fmt.Errorf("finish %s: %w", w.path, err)
	}
	return nil
}

// drop abandons the open member after a failed write.
func (w *Writer) drop() {
	w.f.Close()
	w.f = nil
	w.gen++
	w.pending = false
}

// flush sync-flushes member gen if it is still open.
func (w *Writer) flush(gen uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.f == nil || gen != w.gen || !w.pending {
		return
	}
	w.pending = false
	if err := w.gz.Flush(); err != nil {
		w.drop()
		w.retryAt = w.now().Add(FlushDelay)
		w.fail(fmt.Errorf("flush %s: %w", w.path, err))
	}
}

// prune deletes files of hours that ended more than maxAge before now,
// except current. Other files are never touched.
func (w *Writer) prune(now time.Time, current string) {
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		fmt.Fprintf(w.errOut, "wgsteer: log file: retention: %v\n", err)
		return
	}
	cutoff := now.Add(-w.maxAge)
	for _, e := range entries {
		hour, _, ok := parseName(e.Name())
		if !ok || e.Name() == current || !e.Type().IsRegular() || !hour.Add(time.Hour).Before(cutoff) {
			continue
		}
		if err := os.Remove(filepath.Join(w.dir, e.Name())); err != nil {
			fmt.Fprintf(w.errOut, "wgsteer: log file: retention: %v\n", err)
		}
	}
}

func (w *Writer) fail(err error) {
	if !w.failing {
		w.failing = true
		fmt.Fprintf(w.errOut, "wgsteer: log file: %v (dropping records until a write succeeds)\n", err)
	}
}

// Close finishes the open member; later Writes fail with ErrClosed. A
// failure is also reported on errOut.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	if w.f == nil {
		return nil
	}
	if err := w.finish(); err != nil {
		w.fail(err)
		return err
	}
	return nil
}
