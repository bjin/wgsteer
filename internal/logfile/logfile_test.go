package logfile

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

type testWriter struct {
	*Writer
	t      *testing.T
	at     time.Time
	timers []func()
	errOut bytes.Buffer
}

func newTest(t *testing.T, dir string, maxAge time.Duration, at time.Time) *testWriter {
	tw := &testWriter{t: t, at: at}
	header := func(now time.Time) []byte { return []byte("header " + now.UTC().Format(time.RFC3339) + "\n") }
	tw.Writer = New(dir, maxAge, header, &tw.errOut)
	tw.now = func() time.Time { return tw.at }
	tw.afterFunc = func(d time.Duration, f func()) {
		if d != FlushDelay {
			t.Errorf("flush timer %v, want %v", d, FlushDelay)
		}
		tw.timers = append(tw.timers, f)
	}
	return tw
}

func (tw *testWriter) write(s string) {
	tw.t.Helper()
	if _, err := tw.Write([]byte(s)); err != nil {
		tw.t.Fatal(err)
	}
}

// fireTimers runs the armed flush timers, as time.AfterFunc would after
// FlushDelay.
func (tw *testWriter) fireTimers() {
	timers := tw.timers
	tw.timers = nil
	for _, f := range timers {
		f()
	}
}

// readAll decompresses a complete (possibly multistream) gzip file.
func readAll(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return string(b)
}

// readLogs reads every log file in dir in hour/sequence order the way the
// log readers do: a member cut short by a killed writer (no trailer) yields
// what it holds; anything else that fails to decode is an error.
func readLogs(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	type file struct {
		hour time.Time
		seq  int
		name string
	}
	var files []file
	for _, e := range entries {
		if hour, seq, ok := parseName(e.Name()); ok {
			files = append(files, file{hour, seq, e.Name()})
		}
	}
	slices.SortFunc(files, func(a, b file) int {
		if c := a.hour.Compare(b.hour); c != 0 {
			return c
		}
		return a.seq - b.seq
	})
	var out strings.Builder
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(dir, f.name))
		if err != nil {
			t.Fatal(err)
		}
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			t.Fatalf("%s: %v", f.name, err)
		}
		data, err := io.ReadAll(zr)
		if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("%s: %v (decoded %q)", f.name, err, data)
		}
		out.Write(data)
	}
	return out.String()
}

var t0 = time.Date(2026, 10, 25, 9, 59, 59, 999999999, time.UTC)

func TestRotatesAtUTCHourWithHeader(t *testing.T) {
	dir := t.TempDir()
	// A non-UTC wall clock still names files by the UTC hour.
	w := newTest(t, dir, 168*time.Hour, t0.In(time.FixedZone("UTC+8", 8*3600)))
	w.write("a\n")
	w.at = t0.Add(time.Nanosecond) // 10:00:00 exactly
	w.write("b\n")
	w.write("c\n")
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, filepath.Join(dir, "wgsteer-2026-10-25T09.log.gz")); got != "a\n" {
		t.Errorf("first file %q, want only the record (no header)", got)
	}
	if got := readAll(t, filepath.Join(dir, "wgsteer-2026-10-25T10.log.gz")); got != "header 2026-10-25T10:00:00Z\nb\nc\n" {
		t.Errorf("rotated file %q", got)
	}
	for _, name := range []string{"wgsteer-2026-10-25T09.log.gz", "wgsteer-2026-10-25T10.log.gz"} {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm()&^0o640 != 0 {
			t.Errorf("%s mode %v, want at most 0640", name, st.Mode())
		}
	}
	if _, err := w.Write([]byte("late\n")); !errors.Is(err, ErrClosed) {
		t.Errorf("write after Close: %v", err)
	}
}

// TestReopenStartsNewFile: a restart within the hour never appends to the
// hour's file; it opens the next one (no header: it is the process's first
// file), and each file is one complete gzip member.
func TestReopenStartsNewFile(t *testing.T) {
	dir := t.TempDir()
	for _, s := range []string{"run1\n", "run2\n", "run3\n"} {
		w := newTest(t, dir, 168*time.Hour, t0)
		w.write(s)
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	}
	for name, want := range map[string]string{
		"wgsteer-2026-10-25T09.log.gz":   "run1\n",
		"wgsteer-2026-10-25T09_1.log.gz": "run2\n",
		"wgsteer-2026-10-25T09_2.log.gz": "run3\n",
	} {
		if got := readAll(t, filepath.Join(dir, name)); got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}
	if got := readLogs(t, dir); got != "run1\nrun2\nrun3\n" {
		t.Errorf("all files in order: %q", got)
	}
}

// TestReopenAfterAbandonedWriter: a writer killed without Close (SIGKILL,
// panic, a watchdog exit whose flush timed out) leaves its member without a
// trailer and possibly ending mid-block. A restart within the hour must not
// write behind it, or readers lose every later record of that hour.
func TestReopenAfterAbandonedWriter(t *testing.T) {
	dir := t.TempDir()
	killed := newTest(t, dir, 168*time.Hour, t0)
	killed.write("flushed before the kill\n")
	killed.fireTimers()
	killed.write("still in the compressor\n") // lost with the process

	restarted := newTest(t, dir, 168*time.Hour, t0)
	restarted.write("after the restart\n")
	restarted.fireTimers()
	if got := readLogs(t, dir); got != "flushed before the kill\nafter the restart\n" {
		t.Fatalf("while the restarted writer runs: %q", got)
	}
	restarted.write("later\n")
	if err := restarted.Close(); err != nil {
		t.Fatal(err)
	}
	if got := readLogs(t, dir); got != "flushed before the kill\nafter the restart\nlater\n" {
		t.Fatalf("after its Close: %q", got)
	}
	if got := readAll(t, filepath.Join(dir, "wgsteer-2026-10-25T09_1.log.gz")); got != "after the restart\nlater\n" {
		t.Errorf("restarted file %q", got)
	}
}

// TestFlushMakesDataReadable: before Close, written data becomes readable
// from the unterminated stream once the flush timer fires.
func TestFlushMakesDataReadable(t *testing.T) {
	dir := t.TempDir()
	w := newTest(t, dir, 168*time.Hour, t0)
	w.write("one\n")
	w.write("two\n")
	if len(w.timers) != 1 {
		t.Fatalf("%d flush timers armed, want 1", len(w.timers))
	}
	partial := func() string {
		b, err := os.ReadFile(filepath.Join(dir, Name(t0)))
		if err != nil {
			t.Fatal(err)
		}
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return ""
		}
		out, err := io.ReadAll(zr)
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("unterminated member read: %v", err)
		}
		return string(out)
	}
	if got := partial(); got != "" {
		t.Errorf("data readable before the flush: %q", got)
	}
	w.fireTimers()
	if got := partial(); got != "one\ntwo\n" {
		t.Errorf("after flush %q", got)
	}
	// A new write arms the next flush.
	w.write("three\n")
	w.fireTimers()
	if got := partial(); got != "one\ntwo\nthree\n" {
		t.Errorf("after second flush %q", got)
	}
	// A timer of a finished member is a no-op.
	w.write("four\n")
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	w.fireTimers()
	if got := readAll(t, filepath.Join(dir, Name(t0))); got != "one\ntwo\nthree\nfour\n" {
		t.Errorf("closed file %q", got)
	}
}

// TestRetention: files whose hour ended more than maxAge ago go, at the
// first open and at each rotation, including later files of that hour
// (_N); the files whose hour ended exactly maxAge ago stay, and files not
// named exactly like log files are never touched.
func TestRetention(t *testing.T) {
	dir := t.TempDir()
	keep := []string{
		"wgsteer-2026-10-18T09.log.gz", // ended 10:00, exactly 168 h before 10:00
		"wgsteer-2026-10-18T09_2.log.gz",
		"wgsteer-2026-10-18T08.log",
		"wgsteer-2026-10-18T08.log.gz.1",
		"wgsteer-2026-10-18T8.log.gz",
		"wgsteer-2026-10-18T08:00.log.gz",
		"wgsteer-2026-10-18T08_0.log.gz",
		"wgsteer-2026-10-18T08_01.log.gz",
		"wgsteer-2026-10-18T08_x.log.gz",
		"other-2026-10-18T08.log.gz",
		"notes.txt",
	}
	for _, name := range append([]string{"wgsteer-2026-10-18T08.log.gz", "wgsteer-2026-10-18T08_1.log.gz", "wgsteer-2025-01-01T00.log.gz"}, keep...) {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "wgsteer-2026-10-01T00.log.gz"), 0o700); err != nil {
		t.Fatal(err)
	}
	keep = append(keep, "wgsteer-2026-10-01T00.log.gz")
	names := func() []string {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, e := range entries {
			out = append(out, e.Name())
		}
		return out
	}
	want := func(names ...string) []string {
		out := append(slices.Clone(keep), names...)
		slices.Sort(out)
		return out
	}

	w := newTest(t, dir, 168*time.Hour, time.Date(2026, 10, 25, 10, 0, 0, 0, time.UTC))
	w.write("x\n")
	if got, want := names(), want("wgsteer-2026-10-25T10.log.gz"); !slices.Equal(got, want) {
		t.Fatalf("after first open:\n got %v\nwant %v", got, want)
	}
	// One nanosecond later the 09 file is just older than maxAge, but
	// retention only runs when a file is opened.
	w.at = w.at.Add(time.Nanosecond)
	w.write("y\n")
	if got, want := names(), want("wgsteer-2026-10-25T10.log.gz"); !slices.Equal(got, want) {
		t.Fatalf("retention ran without a rotation:\n got %v\nwant %v", got, want)
	}
	w.at = time.Date(2026, 10, 25, 11, 0, 0, 0, time.UTC)
	w.write("z\n")
	keep = slices.DeleteFunc(keep, func(s string) bool {
		return s == "wgsteer-2026-10-18T09.log.gz" || s == "wgsteer-2026-10-18T09_2.log.gz"
	})
	if got, want := names(), want("wgsteer-2026-10-25T10.log.gz", "wgsteer-2026-10-25T11.log.gz"); !slices.Equal(got, want) {
		t.Fatalf("after rotation:\n got %v\nwant %v", got, want)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestFailureEpisode: an unusable directory is reported once, writes keep
// failing without blocking or retrying before FlushDelay has passed, and
// the first write after that opens a file.
func TestFailureEpisode(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "logs")
	if err := os.WriteFile(dir, nil, 0o600); err != nil { // a file where the directory belongs
		t.Fatal(err)
	}
	start := t0.Add(-30 * time.Minute)
	w := newTest(t, dir, 168*time.Hour, start)
	for range 3 {
		if _, err := w.Write([]byte("lost\n")); err == nil {
			t.Fatal("write into a file path succeeded")
		}
	}
	if n := strings.Count(w.errOut.String(), "\n"); n != 1 {
		t.Fatalf("%d notices, want 1:\n%s", n, w.errOut.String())
	}
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	w.at = start.Add(FlushDelay - time.Nanosecond)
	if _, err := w.Write([]byte("too early\n")); err == nil {
		t.Fatal("retried before FlushDelay had passed")
	}
	if _, err := os.Stat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("an early write touched the log dir: %v", err)
	}
	w.at = start.Add(FlushDelay)
	w.write("kept\n")
	if !strings.Contains(w.errOut.String(), "writing again") {
		t.Errorf("no recovery notice:\n%s", w.errOut.String())
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() || st.Mode().Perm()&^0o750 != 0 {
		t.Errorf("log dir %v %v", st, err)
	}
	if got := readAll(t, filepath.Join(dir, Name(start))); got != "kept\n" {
		t.Errorf("file %q", got)
	}
}
