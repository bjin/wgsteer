// Command wgsteer-replay replays recorded probe samples through the policy
// engine with any endpoint subset and any wgsteer flags. It is the engine
// behind tools/tune.py, which extracts the samples from debug logs.
//
// Stdin is one JSON job:
//
//	{"trace": "trace.tsv", "endpoints": ["ip:port", ...],
//	 "segments": [{"id": 0, "start_us": 1792594211722000, "selection": 9}, ...],
//	 "runs": [{"name": "...", "endpoints": [0, 1, 8, 9], "start": 9,
//	           "args": ["--persist", "60s"], "segments": [1], "decisions": false,
//	           "seed": 1, "faults": [{"at_us": ..., "dur_us": ..., "target": -1,
//	                                  "loss": 1, "add_ms": 0, "tail": 0, "tail_ms": 0}]}, ...]}
//
// trace.tsv has one row per probe slot: segment, slot_us, tick_us, index,
// outcome (r/l/i), rtt_us, logged decision (tab-separated, '#' comments).
// Times are microseconds since the epoch; endpoint indices refer to the
// recorded list.
//
// Each run replays its segments (daemon starts; default all) with a fresh
// engine created at the segment start and the device on endpoint start
// (default: the segment's recorded selection; -1 or an endpoint outside the
// subset: an unlisted endpoint). Samples of endpoints outside the subset are
// skipped, but every row is a tick, so the net-time accumulators advance as
// in the daemon. A reply slower than --probe-timeout counts as a loss. Every
// proposed switch is committed, as in dry-run.
//
// Faults are synthetic events on top of the recorded samples: from at_us for
// dur_us, every valid sample of the target endpoint (recorded index; -1: the
// selection at the first tick at or after at_us) is lost with probability
// loss, and a reply gets add_ms more RTT, plus tail_ms with probability tail.
// Faults must not overlap. Draws use the run's seed.
//
// Stdout is one JSON line per run, in job order: the switches, tick counts
// per blocker, per fault the target and how long the selection stayed on it
// (-1: until the fault ended), and, with "decisions", every tick's decision
// in the logged form (blocker, or switch:kind:to).
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bjin/wgsteer/internal/daemon"
	"github.com/bjin/wgsteer/internal/policy"
	"github.com/bjin/wgsteer/internal/stats"
)

type job struct {
	Trace     string    `json:"trace"`
	Endpoints []string  `json:"endpoints"`
	Segments  []segment `json:"segments"`
	Runs      []run     `json:"runs"`
}

type segment struct {
	ID        int   `json:"id"`
	StartUS   int64 `json:"start_us"`
	Selection int   `json:"selection"`
}

type run struct {
	Name      string   `json:"name"`
	Endpoints []int    `json:"endpoints"`
	Start     *int     `json:"start"`
	Args      []string `json:"args"`
	Segments  []int    `json:"segments"`
	Decisions bool     `json:"decisions"`
	Seed      uint64   `json:"seed"`
	Faults    []fault  `json:"faults"`
}

type fault struct {
	AtUS   int64   `json:"at_us"`
	DurUS  int64   `json:"dur_us"`
	Target int     `json:"target"`
	Loss   float64 `json:"loss"`
	AddMS  float64 `json:"add_ms"`
	Tail   float64 `json:"tail"`
	TailMS float64 `json:"tail_ms"`
}

// faultResult: the endpoint the fault hit (-1: no selection to hit) and the
// time from the fault start to the first switch away from it (-1: none
// before the fault ended).
type faultResult struct {
	AtUS    int64  `json:"at_us"`
	Target  int    `json:"target"`
	LeftUS  int64  `json:"left_us"`
	Kind    string `json:"kind,omitempty"`
	ToIndex int    `json:"to"`
}

type row struct {
	seg     int
	idx     int
	outcome byte
	slot    time.Time
	tick    time.Time
	rtt     time.Duration
}

type switchEvent struct {
	TUS    int64        `json:"t_us"`
	Kind   string       `json:"kind"`
	From   int          `json:"from"`
	To     int          `json:"to"`
	G      policy.Float `json:"g"`
	Reason string       `json:"reason"`
}

type result struct {
	Name      string         `json:"name"`
	Error     string         `json:"error,omitempty"`
	Ticks     int            `json:"ticks"`
	Switches  []switchEvent  `json:"switches"`
	Blockers  map[string]int `json:"blockers"`
	Faults    []faultResult  `json:"faults,omitempty"`
	Decisions []string       `json:"decisions,omitempty"`
}

// requiredArgs satisfy wgsteer's required flags; none of them affects the
// policy. The run's args follow, so the replay takes exactly wgsteer's
// policy flags, defaults and validation.
var requiredArgs = []string{
	"--device", "replay", "--probe-config", "-", "--endpoints", "-",
	"--probe-addr", "192.0.2.1", "--target", "192.0.2.2",
}

func main() {
	if err := replay(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "wgsteer-replay:", err)
		os.Exit(1)
	}
}

func replay(in io.Reader, out io.Writer) error {
	var j job
	dec := json.NewDecoder(in)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&j); err != nil {
		return fmt.Errorf("job: %w", err)
	}
	addrs := make([]netip.AddrPort, len(j.Endpoints))
	for i, s := range j.Endpoints {
		ap, err := netip.ParseAddrPort(s)
		if err != nil {
			return fmt.Errorf("endpoint #%d: %w", i, err)
		}
		addrs[i] = ap
	}
	segs := make(map[int]segment, len(j.Segments))
	for _, s := range j.Segments {
		segs[s.ID] = s
	}
	rows, err := readTrace(j.Trace, len(addrs), segs)
	if err != nil {
		return err
	}

	results := make([]result, len(j.Runs))
	var wg sync.WaitGroup
	next := make(chan int)
	for range runtime.GOMAXPROCS(0) {
		wg.Go(func() {
			for i := range next {
				results[i] = replayRun(j.Runs[i], addrs, rows, segs)
			}
		})
	}
	for i := range j.Runs {
		next <- i
	}
	close(next)
	wg.Wait()

	w := bufio.NewWriter(out)
	enc := json.NewEncoder(w)
	for _, r := range results {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	return w.Flush()
}

func readTrace(path string, n int, segs map[int]segment) ([]row, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var rows []row
	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		text := sc.Text()
		if text == "" || text[0] == '#' {
			continue
		}
		fields := strings.Split(text, "\t")
		if len(fields) < 6 {
			return nil, fmt.Errorf("%s:%d: want at least 6 fields, got %d", path, line, len(fields))
		}
		var v [5]int64
		for i, k := range []int{0, 1, 2, 3, 5} {
			if v[i], err = strconv.ParseInt(fields[k], 10, 64); err != nil {
				return nil, fmt.Errorf("%s:%d: field %d: %w", path, line, k+1, err)
			}
		}
		r := row{seg: int(v[0]), slot: time.UnixMicro(v[1]), tick: time.UnixMicro(v[2]), idx: int(v[3]),
			rtt: time.Duration(v[4]) * time.Microsecond}
		if len(fields[4]) != 1 || !strings.Contains("rli", fields[4]) {
			return nil, fmt.Errorf("%s:%d: outcome %q", path, line, fields[4])
		}
		r.outcome = fields[4][0]
		if r.idx < 0 || r.idx >= n {
			return nil, fmt.Errorf("%s:%d: endpoint index %d out of range", path, line, r.idx)
		}
		if _, ok := segs[r.seg]; !ok {
			return nil, fmt.Errorf("%s:%d: unknown segment %d", path, line, r.seg)
		}
		if len(rows) > 0 && rows[len(rows)-1].seg > r.seg {
			return nil, fmt.Errorf("%s:%d: segments out of order", path, line)
		}
		rows = append(rows, r)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errors.New(path + ": no samples")
	}
	return rows, nil
}

func replayRun(rs run, addrs []netip.AddrPort, rows []row, segs map[int]segment) result {
	res := result{Name: rs.Name, Switches: []switchEvent{}, Blockers: map[string]int{}}
	fail := func(err error) result {
		res.Error = err.Error()
		return res
	}
	cfg, err := daemon.ParseFlags(append(slices.Clone(requiredArgs), rs.Args...), daemon.DefaultConfig(), io.Discard)
	if err != nil {
		return fail(fmt.Errorf("flags: %w", err))
	}
	p := cfg.Params()
	if len(rs.Endpoints) == 0 {
		return fail(errors.New("empty endpoint subset"))
	}
	pos := slices.Repeat([]int{-1}, len(addrs)) // recorded index → subset position
	list := make([]netip.AddrPort, len(rs.Endpoints))
	for k, i := range rs.Endpoints {
		if i < 0 || i >= len(addrs) || pos[i] >= 0 {
			return fail(fmt.Errorf("bad or duplicate endpoint index %d", i))
		}
		pos[i] = k
		list[k] = addrs[i]
	}
	for _, id := range rs.Segments {
		if _, ok := segs[id]; !ok {
			return fail(fmt.Errorf("unknown segment %d", id))
		}
	}
	for i, f := range rs.Faults {
		switch {
		case f.DurUS <= 0:
			return fail(fmt.Errorf("fault %d: dur_us must be positive", i))
		case i > 0 && f.AtUS < rs.Faults[i-1].AtUS+rs.Faults[i-1].DurUS:
			return fail(fmt.Errorf("fault %d overlaps or precedes fault %d", i, i-1))
		case f.Target < -1 || f.Target >= len(addrs) || f.Target >= 0 && pos[f.Target] < 0:
			return fail(fmt.Errorf("fault %d: target %d is not in the subset", i, f.Target))
		case f.Loss < 0 || f.Loss > 1 || f.Tail < 0 || f.Tail > 1:
			return fail(fmt.Errorf("fault %d: loss and tail must be in [0, 1]", i))
		}
		res.Faults = append(res.Faults, faultResult{AtUS: f.AtUS, Target: -1, LeftUS: -1, ToIndex: -1})
	}
	rng := rand.New(rand.NewPCG(rs.Seed, rs.Seed^0x9e3779b97f4a7c15))
	fi, hit := 0, -1 // current fault and its resolved target (-1: none)
	selected := func(eng *policy.Engine) int { return slices.Index(addrs, eng.Selected()) }

	var eng *policy.Engine
	seg := -1
	for _, r := range rows {
		if len(rs.Segments) > 0 && !slices.Contains(rs.Segments, r.seg) {
			continue
		}
		if r.seg != seg {
			seg = r.seg
			start := segs[seg].Selection
			if rs.Start != nil {
				start = *rs.Start
			}
			var sel netip.AddrPort
			if start >= 0 && start < len(addrs) && pos[start] >= 0 {
				sel = addrs[start]
			}
			if eng, err = policy.New(p, list, sel, time.UnixMicro(segs[seg].StartUS)); err != nil {
				return fail(err)
			}
		}
		tick := r.tick.UnixMicro()
		for fi < len(rs.Faults) && tick >= rs.Faults[fi].AtUS+rs.Faults[fi].DurUS {
			fi, hit = fi+1, -1
		}
		var f *fault
		if fi < len(rs.Faults) && tick >= rs.Faults[fi].AtUS {
			f = &rs.Faults[fi]
			if res.Faults[fi].Target < 0 && hit < 0 {
				hit = f.Target
				if hit < 0 {
					hit = selected(eng)
				}
				res.Faults[fi].Target = hit
			}
		}
		if k := pos[r.idx]; k >= 0 {
			if r.outcome == 'i' {
				eng.RecordInvalid(list[k], r.slot)
			} else {
				ok := r.outcome == 'r' && r.rtt <= cfg.ProbeTimeout
				rtt := r.rtt
				if slot := r.slot.UnixMicro(); f != nil && r.idx == hit && slot >= f.AtUS && slot < f.AtUS+f.DurUS {
					lost, tail := rng.Float64() < f.Loss, rng.Float64() < f.Tail
					rtt += time.Duration(f.AddMS * float64(time.Millisecond))
					if tail {
						rtt += time.Duration(f.TailMS * float64(time.Millisecond))
					}
					ok = ok && !lost && rtt <= cfg.ProbeTimeout
				}
				if !ok {
					rtt = 0
				}
				eng.Record(list[k], stats.Sample{At: r.slot, Replied: ok, RTT: rtt})
			}
		}
		d := eng.Tick(r.tick)
		res.Ticks++
		key := string(d.Blocker)
		if d.Switch {
			key = "switch:" + string(d.Kind) + ":" + d.To.String()
			var g policy.Float
			for _, v := range d.Record.Endpoints {
				if v.Addr == d.To && v.Gate != nil {
					g = v.Gate.G
				}
			}
			res.Switches = append(res.Switches, switchEvent{TUS: r.tick.UnixMicro(), Kind: string(d.Kind),
				From: slices.Index(addrs, d.From), To: slices.Index(addrs, d.To), G: g, Reason: d.Reason})
			eng.Commit(d, r.tick)
			if f != nil && hit >= 0 && res.Faults[fi].LeftUS < 0 && selected(eng) != hit {
				fr := &res.Faults[fi]
				fr.LeftUS, fr.Kind, fr.ToIndex = tick-f.AtUS, string(d.Kind), selected(eng)
			}
			res.Blockers["switch"]++
		} else {
			res.Blockers[key]++
		}
		if rs.Decisions {
			res.Decisions = append(res.Decisions, key)
		}
	}
	return res
}
