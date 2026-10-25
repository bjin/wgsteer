#!/usr/bin/env python3
"""Offline analysis and parameter tuning on recorded wgsteer probe samples.

A dry-run at --log-level debug logs every probe sample. This tool extracts
them once, characterizes the paths, and replays them through the real policy
engine (cmd/wgsteer-replay, built on demand) for any endpoint subset and any
flag set:

  extract LOGS...      parse debug logs (wgsteer-*.log.gz or .log) into --data
  verify               replay the recorded runs with their own flags; every
                       logged decision must be reproduced
  paths                per-endpoint loss/RTT, by hour, loss runs, common-mode
                       losses, wg0 ground truth
  replay [-- FLAGS]    one flag set on the presets: switches and quality,
                       against the defaults and the best static endpoint
  faults [-- FLAGS]    synthetic faults on the active endpoint, on top of the
                       recorded samples: how long the selection stays on it
  tune                 grid search: quality and churn on the recorded data,
                       fault exposure for the best configs, Pareto set, pick

Presets (--preset NAME=SPEC, repeatable; default all endpoints) are endpoint
subsets by index into the recorded list, kept in list order. SPEC is a
comma list of indices and ranges, optionally +K:SPEC for every way to add K
more: p3=0,1,8,9+2:4-7 is six presets p3+45, p3+46, ... Each preset is
replayed at the recorded per-endpoint period (N endpoints x
--probe-interval), i.e. as if deployed with --probe-interval scaled by N/n;
the samples a faster schedule would take do not exist. --probe-interval is
therefore set per preset and cannot be passed.

Quality is judged with hindsight on a 10 s grid, per endpoint, from the
cost model of docs/scoring.md at reference weights (alpha 7, k 2.5) over a
centered window of the endpoint's own samples (+-5 min RTT, +-30 min loss):
  regret       active cost minus the preset's best cost (ms, time average)
  pref regret  the same with the reference order bias (1 + 0.02 x position):
               against the endpoint the list preference would pick
  worse        time share on an endpoint costing > 1.18x the best
  loss/rtt     raw probe samples of whichever endpoint was active
  out probes   active-endpoint losses inside a run of >= 2 (visible outages)
  flaps        switch back to the previous endpoint within 15 min
Objective J = pref regret + LAMBDA x switches/day (--switch-cost, ms per
switch/day); R = J / J(defaults), averaged over presets (1 = defaults).
Fault exposure F: mean time on the faulted endpoint during each fault,
relative to the defaults, averaged over fault kinds and presets.
"""

import argparse
import bisect
import collections
import datetime
import glob
import gzip
import itertools
import json
import math
import os
import re
import shutil
import statistics
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

PAIR = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S*)')
SAMPLE = re.compile(
    r"^time=\S+ level=DEBUG msg=sample endpoint=\S+ index=(\d+) seq=\d+ outcome=(\w+) "
    r"rtt_ms=(\S+) slot_start=(\S+) finished_after_ms=(\S+)"
)
DECISION = re.compile(r'^time=\S+ level=DEBUG msg="trace decision" switch=(\w+) kind=(\S*) to=(\S+) blocker=(\S*) ')

# Flags of the policy, as in wgsteer's command line. Durations are Go syntax.
DURATION_FLAGS = ("probe_interval", "persist", "cooldown", "wait_to_restore", "margin_abs")
INT_FLAGS = ("history", "min_samples")
FLOAT_FLAGS = ("half_life", "noise_gate", "loss_weight", "jitter_weight", "order_bias", "margin", "outage_epsilon")
POLICY_FLAGS = DURATION_FLAGS + INT_FLAGS + FLOAT_FLAGS


def die(msg):
    print("tune.py: " + msg, file=sys.stderr)
    sys.exit(1)


def unquote(v):
    if v.startswith('"'):
        return json.loads(v)
    return v


def pairs(line):
    return {k: unquote(v) for k, v in PAIR.findall(line)}


def us(stamp):
    """RFC 3339 time with Z suffix to integer microseconds since the epoch."""
    d = datetime.datetime.fromisoformat(stamp)
    return int(round(d.timestamp() * 1e6))


def go_duration_us(s):
    """Go duration string (as logged: 45s, 5m0s, 500ms, 1h0m0s) to microseconds."""
    total, num = 0.0, ""
    units = {"h": 3600e6, "m": 60e6, "s": 1e6, "ms": 1e3, "us": 1.0, "µs": 1.0, "ns": 1e-3}
    i = 0
    while i < len(s):
        c = s[i]
        if c.isdigit() or c == ".":
            num += c
            i += 1
            continue
        for u in ("ms", "us", "µs", "ns", "h", "m", "s"):
            if s.startswith(u, i):
                total += float(num) * units[u]
                num = ""
                i += len(u)
                break
        else:
            raise ValueError("bad duration %r" % s)
    if num:
        if float(num) != 0:
            raise ValueError("bad duration %r" % s)
    return int(round(total))


# ---------------------------------------------------------------------------
# extract


def parse_file(path):
    """One log file: samples (with the decision logged right after each) and
    the info lines needed to reconstruct the daemon runs."""
    opener = gzip.open if path.endswith(".gz") else open
    samples, infos = [], []
    with opener(path, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            if " msg=sample " in line:
                m = SAMPLE.match(line)
                if m:
                    idx, outcome, rtt, slot, after = m.groups()
                    slot_us = us(slot)
                    samples.append([slot_us, slot_us + int(round(float(after) * 1000)), int(idx), outcome[0],
                                    int(round(float(rtt) * 1000)), "-"])
                continue
            if ' msg="trace decision" ' in line:
                m = DECISION.match(line)
                if m and samples and samples[-1][5] == "-":
                    sw, kind, to, blocker = m.groups()
                    samples[-1][5] = "switch:%s:%s" % (unquote(kind), to) if sw == "true" else (blocker or "none")
                continue
            if " level=DEBUG " in line:
                continue
            for key in (" msg=starting ", " msg=config ", " msg=endpoint ", ' msg="initial selection" ',
                        ' msg="would switch" ', " msg=switch ", " msg=stopped", ' msg="run.sh wg0 ping" ',
                        ' msg="device handshake stale" ', ' msg="probe session expired" ',
                        ' msg="probe session established" ', ' msg="endpoints reloaded" '):
                if key in line:
                    infos.append(pairs(line.rstrip("\n")))
                    break
    return path, samples, infos


def cmd_extract(a):
    files = []
    for arg in a.logs:
        if os.path.isdir(arg):
            files += glob.glob(os.path.join(arg, "wgsteer-*.log.gz")) + glob.glob(os.path.join(arg, "wgsteer-*.log"))
        else:
            files += glob.glob(arg)
    files = sorted(set(files))
    if not files:
        die("no log files in " + " ".join(a.logs))
    with ProcessPoolExecutor() as ex:
        parsed = list(ex.map(parse_file, files))

    rows, infos = [], []
    for _, s, i in parsed:
        rows += s
        infos += i
    rows.sort(key=lambda r: r[1])
    infos.sort(key=lambda r: us(r["time"]))

    # Daemon runs: each "starting" begins a segment; the engine is created at
    # "initial selection" with the logged config and endpoint list.
    segments, cur = [], None
    events, pings, stale, sessions = [], [], [], []
    for r in infos:
        msg, t = r["msg"], us(r["time"])
        if msg == "starting":
            cur = {"id": len(segments), "pid": r.get("pid"), "endpoints": [], "config": {}}
            segments.append(cur)
        elif msg == "config" and cur is not None:
            cur["config"] = {k: r[k] for k in POLICY_FLAGS + ("probe_timeout", "dry_run") if k in r}
        elif msg == "endpoint" and cur is not None:
            cur["endpoints"].append(r["endpoint"])
        elif msg == "initial selection" and cur is not None:
            cur["start_us"] = t
            cur["selection"] = int(r["index"])
        elif msg == "stopped" and cur is not None:
            cur["stop_us"] = t
        elif msg in ("would switch", "switch"):
            events.append({"t_us": t, "segment": cur["id"] if cur else None, "kind": r["kind"], "from": r["from"],
                           "to": r["to"], "g": r.get("g"), "dry_run": msg == "would switch"})
        elif msg == "run.sh wg0 ping":
            pings.append({"t_us": t, **{k: r[k] for k in r if k not in ("time", "level", "msg")}})
        elif msg == "device handshake stale":
            stale.append({"t_us": t, "handshake_age": r.get("handshake_age"), "selection": r.get("selection")})
        elif msg in ("probe session expired", "probe session established"):
            sessions.append({"t_us": t, "msg": msg})
        elif msg == "endpoints reloaded":
            die("the log contains a SIGHUP reload; replaying list changes is not supported")
    segments = [s for s in segments if "start_us" in s]
    if not segments:
        die("no daemon start (msg=starting ... initial selection) in the logs")
    lists = {tuple(s["endpoints"]) for s in segments}
    if len(lists) != 1:
        die("the endpoint list differs between daemon runs; extract each run separately")
    endpoints = segments[0]["endpoints"]

    # Assign samples to segments by tick time.
    starts = [s["start_us"] for s in segments]
    os.makedirs(a.data, exist_ok=True)
    counts = collections.Counter()
    with open(os.path.join(a.data, "trace.tsv"), "w") as f:
        f.write("# segment\tslot_us\ttick_us\tindex\toutcome\trtt_us\tlogged_decision\n")
        for slot_us, tick_us, idx, outcome, rtt_us, dec in rows:
            seg = bisect.bisect_right(starts, tick_us) - 1
            if seg < 0 or tick_us > segments[seg].get("stop_us", 1 << 62):
                counts["outside"] += 1
                continue
            f.write("%d\t%d\t%d\t%d\t%s\t%d\t%s\n" % (seg, slot_us, tick_us, idx, outcome, rtt_us, dec))
            counts[outcome] += 1
            segments[seg]["end_us"] = tick_us
    meta = {"endpoints": endpoints, "segments": segments, "events": events, "wg0_pings": pings,
            "handshake_stale": stale, "probe_sessions": sessions, "files": len(files)}
    with open(os.path.join(a.data, "meta.json"), "w") as f:
        json.dump(meta, f, indent=1)
    span = sum(s.get("end_us", s["start_us"]) - s["start_us"] for s in segments) / 3600e6
    print("%d files, %d daemon run(s), %.1f h, %d endpoints; samples: %d reply, %d loss, %d invalid (%d outside a run); "
          "%d logged switch(es)" % (len(files), len(segments), span, len(endpoints), counts["r"], counts["l"],
                                    counts["i"], counts["outside"], len(events)))
    print("wrote %s/trace.tsv and %s/meta.json" % (a.data, a.data))


# ---------------------------------------------------------------------------
# loading


class Data:
    def __init__(self, path):
        try:
            with open(os.path.join(path, "meta.json")) as f:
                self.meta = json.load(f)
        except FileNotFoundError:
            die("no extracted data in %s; run 'extract' first" % path)
        self.dir = path
        self.trace = os.path.join(path, "trace.tsv")
        self.endpoints = self.meta["endpoints"]
        self.segments = self.meta["segments"]
        self.n = len(self.endpoints)
        cfg = self.segments[-1]["config"]
        self.interval_us = go_duration_us(cfg.get("probe_interval", "1s"))
        self.timeout_us = go_duration_us(cfg.get("probe_timeout", "500ms"))
        # per endpoint: sorted lists of (slot_us, replied, rtt_ms) for valid samples
        self.samples = [[] for _ in range(self.n)]
        # per row (= daemon tick): (segment, tick_us, logged decision)
        self.ticks = []
        with open(self.trace) as f:
            for line in f:
                if line[0] == "#":
                    continue
                seg, slot, tick, idx, outcome, rtt, logged = line.rstrip("\n").split("\t")
                self.ticks.append((int(seg), int(tick), logged))
                if outcome == "i":
                    continue
                self.samples[int(idx)].append((int(slot), outcome == "r", int(rtt) / 1000.0))
        self.t0 = min(s["start_us"] for s in self.segments)
        self.t1 = max(s.get("end_us", s["start_us"]) for s in self.segments)

    def label(self, i):
        return "#%d %s" % (i, self.endpoints[i])


def config_args(cfg):
    """wgsteer flags of the policy from a logged config line."""
    args = []
    for k in POLICY_FLAGS + ("probe_timeout",):
        if k in cfg:
            args += ["--" + k.replace("_", "-"), cfg[k]]
    return args


# ---------------------------------------------------------------------------
# replay


def replay_bin(a):
    if a.replay_bin:
        return a.replay_bin
    if not getattr(a, "_replay_built", None):
        out = os.path.abspath(os.path.join(a.data, "wgsteer-replay"))
        go = shutil.which("go") or die("go not found; build cmd/wgsteer-replay and pass --replay-bin")
        subprocess.run([go, "build", "-o", out, "./cmd/wgsteer-replay"], cwd=REPO, check=True)
        a._replay_built = out
    return a._replay_built


def run_replay(a, data, runs, trace=None):
    """Run the replay engine; one result dict per run, in order."""
    job = {
        "trace": os.path.abspath(trace or data.trace),
        "endpoints": data.endpoints,
        "segments": [{"id": s["id"], "start_us": s["start_us"], "selection": s["selection"]} for s in data.segments],
        "runs": runs,
    }
    p = subprocess.run([replay_bin(a)], input=json.dumps(job), capture_output=True, text=True)
    if p.returncode != 0:
        die("wgsteer-replay failed: " + p.stderr.strip())
    results = [json.loads(line) for line in p.stdout.splitlines()]
    for r in results:
        if r.get("error"):
            die("replay %s: %s" % (r["name"], r["error"]))
    return results


def local_time(t_us, tz_hours):
    if tz_hours is None:
        d = datetime.datetime.fromtimestamp(t_us / 1e6)
    else:
        d = datetime.datetime.fromtimestamp(t_us / 1e6, datetime.timezone(datetime.timedelta(hours=tz_hours)))
    return d.strftime("%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# evaluation
#
# Quality is judged with hindsight on a 10 s grid: per endpoint, the cost
# model of docs/scoring.md (L = mean + k*sd, F = 1 + alpha*p/(1-p), with the
# reference alpha 7 and k 2.5 whatever the replayed flags are) over a centered
# window of that endpoint's own samples: +-5 min for RTT, +-30 min for loss
# (at 10 s per sample a 10-min window resolves loss only in 1.7% steps).
# Regret is the active endpoint's cost minus the best endpoint's of the
# preset; "pref" regret compares costs with the reference order bias
# (1 + 0.02 * position) applied, i.e. against the endpoint the list order
# would pick. "worse" is the time share on an endpoint costing more than 1.18x
# the best (a fixed reference, independent of --margin). Experienced loss/RTT
# are the raw probe samples of whichever endpoint was active at the time.

CELL_US = 10_000_000
REF_ALPHA, REF_K, REF_BIAS, REF_WORSE = 7.0, 2.5, 0.02, 1.18
RTT_WINDOW_US, LOSS_WINDOW_US = 300_000_000, 1_800_000_000


class Truth:
    def __init__(self, data):
        self.data = data
        # cells: the grid of every daemon run (segment), concatenated
        self.cell0, self.ncells = {}, {}
        self.times = []
        for s in data.segments:
            self.cell0[s["id"]] = len(self.times)
            t = s["start_us"]
            while t + CELL_US <= s.get("end_us", s["start_us"]):
                self.times.append(t)
                t += CELL_US
            self.ncells[s["id"]] = len(self.times) - self.cell0[s["id"]]
        self.nc = len(self.times)
        # per endpoint and cell: (mean, sd, loss) or None if unusable
        self.comp = [self._series(i) for i in range(data.n)]
        self.cost = [[cost(*c) if c else UNUSABLE for c in comp] for comp in self.comp]
        # experienced-sample prefix sums per endpoint: n, lost, rtt sum,
        # losses inside a run of at least 2 (an outage the user would see)
        self.exp = []
        for xs in data.samples:
            ts, n, lost, rsum, run2 = [], [0], [0], [0.0], [0]
            runlen = [0] * len(xs)
            r = 0
            for k in range(len(xs) - 1, -1, -1):  # run length through each loss, both directions
                r = r + 1 if not xs[k][1] else 0
                runlen[k] = r
            r = 0
            for k, (t, ok, rtt) in enumerate(xs):
                r = r + 1 if not ok else 0
                total = r + runlen[k] - 1 if not ok else 0
                ts.append(t)
                n.append(n[-1] + 1)
                lost.append(lost[-1] + (0 if ok else 1))
                rsum.append(rsum[-1] + (rtt if ok else 0.0))
                run2.append(run2[-1] + (1 if total >= 2 else 0))
            self.exp.append((ts, n, lost, rsum, run2))

    def _series(self, i):
        xs = self.data.samples[i]
        ts = [s[0] for s in xs]
        cn, cr, c1, c2 = [0], [0], [0.0], [0.0]
        for _, ok, rtt in xs:
            cn.append(cn[-1] + 1)
            cr.append(cr[-1] + (1 if ok else 0))
            c1.append(c1[-1] + (rtt if ok else 0.0))
            c2.append(c2[-1] + (rtt * rtt if ok else 0.0))
        out = []
        for t in self.times:
            mid = t + CELL_US // 2
            lo, hi = bisect.bisect_left(ts, mid - RTT_WINDOW_US), bisect.bisect_right(ts, mid + RTT_WINDOW_US)
            r = cr[hi] - cr[lo]
            llo, lhi = bisect.bisect_left(ts, mid - LOSS_WINDOW_US), bisect.bisect_right(ts, mid + LOSS_WINDOW_US)
            n = cn[lhi] - cn[llo]
            p = 1 - (cr[lhi] - cr[llo]) / n if n else 1.0
            if r < 2 or p >= 0.99:
                out.append(None)
                continue
            m = (c1[hi] - c1[lo]) / r
            out.append((m, math.sqrt(max((c2[hi] - c2[lo]) / r - m * m, 0.0)), p))
        return out

    def faulted_cost(self, i, t_us, f):
        """Hindsight cost of endpoint i at t_us with fault f applied."""
        c = self.comp[i][min(max(bisect.bisect_right(self.times, t_us) - 1, 0), self.nc - 1)]
        if not c:
            return UNUSABLE
        m, sd, p = c
        p = 1 - (1 - p) * (1 - f.get("loss", 0))
        q, x = f.get("tail", 0), f.get("tail_ms", 0)
        m, sd = m + f.get("add_ms", 0) + q * x, math.sqrt(sd * sd + q * (1 - q) * x * x)
        return cost(m, sd, p) if p < 0.99 else UNUSABLE

    def cell_cost(self, i, t_us):
        return self.cost[i][min(max(bisect.bisect_right(self.times, t_us) - 1, 0), self.nc - 1)]


UNUSABLE = 10_000.0  # no usable samples: as bad as an outage


def cost(mean, sd, p):
    return (mean + REF_K * sd) * (1 + REF_ALPHA * p / (1 - p))


class PresetEval:
    """Prefix sums over the grid for one preset, so that a run's metrics cost
    O(switches)."""

    def __init__(self, truth, preset):
        self.t, self.preset = truth, preset
        nc = truth.nc
        best = [min(truth.cost[e][c] for e in preset) for c in range(nc)]
        bias = {e: 1 + REF_BIAS * k for k, e in enumerate(preset)}
        pbest = [min(truth.cost[e][c] * bias[e] for e in preset) for c in range(nc)]
        self.best = self._prefix(best)
        self.pbest = self._prefix(pbest)
        self.cost = {e: self._prefix(truth.cost[e]) for e in preset}
        self.pcost = {e: self._prefix([x * bias[e] for x in truth.cost[e]]) for e in preset}
        self.worse = {e: self._prefix([1 if truth.cost[e][c] > REF_WORSE * best[c] else 0 for c in range(nc)])
                      for e in preset}

    @staticmethod
    def _prefix(xs):
        out = [0.0]
        for x in xs:
            out.append(out[-1] + x)
        return out

    def spans(self, result, start):
        """(endpoint or None, first cell, end cell, t0_us, t1_us) of constant
        selection; every daemon run starts on start (None: the recorded one),
        or on none if that is not in the preset."""
        t = self.t
        by_seg = collections.defaultdict(list)
        for e in result["switches"]:
            by_seg[self._segment(e["t_us"])].append(e)
        out = []
        for s in t.data.segments:
            c0 = t.cell0[s["id"]]
            nseg = t.ncells[s["id"]]
            cur = s["selection"] if start is None else start
            cur = cur if cur in self.preset else None
            c, tt = c0, s["start_us"]
            for e in by_seg.get(s["id"], []):
                ce = c0 + min(max((e["t_us"] - s["start_us"]) // CELL_US, 0), nseg)
                out.append((cur, c, ce, tt, e["t_us"]))
                cur, c, tt = e["to"], ce, e["t_us"]
            out.append((cur, c, c0 + nseg, tt, s.get("end_us", s["start_us"])))
        return out

    def _segment(self, t_us):
        segs = self.t.data.segments
        k = bisect.bisect_right([s["start_us"] for s in segs], t_us) - 1
        return segs[max(k, 0)]["id"]

    def evaluate(self, result, start, window=None):
        """Metrics of one replay result; window=(t0_us, t1_us) restricts
        everything (time on endpoints and switches) to that interval."""
        t = self.t
        w0, w1 = window or (-1, 1 << 62)
        reg = preg = worse = cells = 0.0
        n = lost = run2 = 0
        rsum = 0.0
        share = collections.Counter()
        for e, c0, c1, t0, t1 in self.spans(result, start):
            if w0 > t0 or t1 > w1:  # clip to the window
                t0, t1 = max(t0, w0), min(t1, w1)
                if t1 <= t0:
                    continue
                c0 = max(c0, bisect.bisect_left(t.times, w0))
                c1 = min(c1, bisect.bisect_left(t.times, w1))
            if e is None or c1 <= c0:
                continue
            cells += c1 - c0
            share[e] += c1 - c0
            reg += (self.cost[e][c1] - self.cost[e][c0]) - (self.best[c1] - self.best[c0])
            preg += (self.pcost[e][c1] - self.pcost[e][c0]) - (self.pbest[c1] - self.pbest[c0])
            worse += self.worse[e][c1] - self.worse[e][c0]
            ts, cn, cl, cr, c2 = t.exp[e]
            lo, hi = bisect.bisect_left(ts, t0), bisect.bisect_left(ts, t1)
            n += cn[hi] - cn[lo]
            lost += cl[hi] - cl[lo]
            rsum += cr[hi] - cr[lo]
            run2 += c2[hi] - c2[lo]
        days = sum(max(min(s.get("end_us", s["start_us"]), w1) - max(s["start_us"], w0), 0)
                   for s in t.data.segments) / 86400e6
        sw = [e for e in result["switches"] if w0 <= e["t_us"] < w1]
        kinds = collections.Counter(e["kind"] for e in sw)
        flaps = sum(1 for x, y in zip(sw, sw[1:]) if y["to"] == x["from"] and y["t_us"] - x["t_us"] <= 900e6)
        cells = cells or 1
        return {
            "regret": reg / cells, "pref_regret": preg / cells, "worse": worse / cells,
            "loss": lost / n if n else float("nan"), "rtt": rsum / (n - lost) if n > lost else float("nan"),
            "outage_probes": run2, "switches_day": len(sw) / days, "switches": len(sw), "days": days,
            "kinds_day": {k: v / days for k, v in kinds.items()}, "flaps": flaps,
            "share": {e: v / cells for e, v in sorted(share.items())},
        }

# ---------------------------------------------------------------------------
# verify


def cmd_verify(a):
    """The log has wall times rounded to the millisecond, the daemon used
    CLOCK_BOOTTIME. Slots sit on a 1-interval grid, so a net-time accumulator
    reaches its limit within microseconds of a tick and the exact tick can
    differ by one. Verification therefore requires the same switches (kind,
    from, to) at most one tick apart, and every other decision identical."""
    data = Data(a.data)
    runs = [{"name": "segment %d" % s["id"], "endpoints": list(range(data.n)), "segments": [s["id"]],
             "args": config_args(s["config"]), "decisions": True} for s in data.segments]
    results = run_replay(a, data, runs)
    bad = 0
    ties = 0
    for s, r in zip(data.segments, results):
        logged = [(t, d) for seg, t, d in data.ticks if seg == s["id"]]
        got = r["decisions"]
        if len(got) != len(logged):
            die("segment %d: %d replayed ticks, %d logged" % (s["id"], len(got), len(logged)))
        lsw = [i for i, (_, d) in enumerate(logged) if d.startswith("switch:")]
        rsw = [i for i, d in enumerate(got) if d.startswith("switch:")]
        same = len(lsw) == len(rsw) and all(
            logged[i][1] == got[j] and abs(i - j) <= 1 for i, j in zip(lsw, rsw))
        near = {k for i in lsw + rsw for k in (i - 1, i, i + 1)}
        miss = [i for i, ((_, d), g) in enumerate(zip(logged, got)) if d != "-" and d != g]
        real = [i for i in miss if not same or i not in near]
        shifted = sum(1 for i, j in zip(lsw, rsw) if i != j) if same else 0
        unlogged = sum(1 for _, d in logged if d == "-")
        print("segment %d (%s, %.1f h): %d ticks, %d logged / %d replayed switches (%d one tick apart), "
              "%d other decision mismatch(es)%s" % (
                  s["id"], local_time(s["start_us"], a.tz), (s.get("end_us", s["start_us"]) - s["start_us"]) / 3600e6,
                  len(got), len(lsw), len(rsw), shifted, len(real),
                  ", %d ticks without a logged decision" % unlogged if unlogged else ""))
        if not same:
            print("  switch sequence differs:")
            for i in lsw:
                print("    logged   %s %s" % (local_time(logged[i][0], a.tz), logged[i][1]))
            for j in rsw:
                print("    replayed %s %s" % (local_time(logged[j][0], a.tz), got[j]))
            bad += 1
        for i in real[:10]:
            print("  %s logged %s, replayed %s" % (local_time(logged[i][0], a.tz), logged[i][1], got[i]))
        bad += len(real)
        ties += shifted
    if bad:
        die("replay does not reproduce the logged decisions")
    print("OK: all decisions reproduced (%d switch(es) one tick apart: accumulator ties)" % ties)


# ---------------------------------------------------------------------------
# paths


def tz_hours(a):
    if a.tz is not None:
        return a.tz
    return datetime.datetime.now().astimezone().utcoffset().total_seconds() / 3600


def cmd_paths(a):
    data = Data(a.data)
    tz = tz_hours(a)
    hour_of = lambda t: int(((t / 1e6 + tz * 3600) // 3600) % 24)
    period = data.interval_us * data.n / 1e6
    print("%d endpoints, %.1f h, each probed every %.0f s" % (data.n, (data.t1 - data.t0) / 3600e6, period))
    print("\nWhole run: loss, RTT percentiles (ms), loss runs (consecutive losses in the endpoint's own samples)")
    print("  #  endpoint                                      samples   loss    p50    p90    p99    max  runs 1/2/3+  longest")
    for i in range(data.n):
        xs = data.samples[i]
        rt = sorted(s[2] for s in xs if s[1])
        runs, r = collections.Counter(), 0
        for s in xs + [(0, True, 0)]:
            if not s[1]:
                r += 1
            elif r:
                runs[min(r, 3)] += 1
                runs["max"] = max(runs["max"], r)
                r = 0
        q = lambda p: rt[min(int(p * len(rt)), len(rt) - 1)] if rt else float("nan")
        print("%3d  %-44s %7d %5.1f%% %6.1f %6.1f %6.1f %6.1f  %4d/%d/%d  %7d" % (
            i, data.endpoints[i], len(xs), 100 * (1 - len(rt) / len(xs)) if xs else 0, q(.5), q(.9), q(.99),
            rt[-1] if rt else float("nan"), runs[1], runs[2], runs[3], runs["max"]))

    print("\nBy hour of day (UTC%+g): median RTT ms / RTT sd ms / loss %%" % tz)
    print("hh " + "".join("  %-16s" % ("#%d" % i) for i in range(data.n)))
    for h in range(24):
        cells = []
        for i in range(data.n):
            xs = [s for s in data.samples[i] if hour_of(s[0]) == h]
            rt = sorted(s[2] for s in xs if s[1])
            if len(rt) < 2:
                cells.append("-")
                continue
            m = sum(rt) / len(rt)
            sd = math.sqrt(max(sum(x * x for x in rt) / len(rt) - m * m, 0))
            cells.append("%3.0f/%4.1f/%4.1f" % (rt[len(rt) // 2], sd, 100 * (1 - len(rt) / len(xs))))
        print("%02d " % h + "".join("  %-16s" % c for c in cells))

    # Common-mode losses: one round = every endpoint probed once.
    rnd = collections.defaultdict(dict)
    for i in range(data.n):
        for t, ok, _ in data.samples[i]:
            rnd[int((t - data.t0) // (data.interval_us * data.n))][i] = ok
    clean = [i for i in range(data.n) if data.samples[i] and
             sum(1 for s in data.samples[i] if not s[1]) / len(data.samples[i]) < 0.01]
    hist = collections.Counter(sum(1 for i in clean if i in v and not v[i]) for v in rnd.values())
    print("\nCommon-mode losses among the endpoints under 1%% loss (%s): rounds by number of them lost in the "
          "same round: %s" % (",".join(map(str, clean)), ", ".join("%d: %d" % kv for kv in sorted(hist.items()))))

    pings = data.meta.get("wg0_pings", [])
    if pings:
        print("\nwg0 ground truth (run.sh pings through wg0) vs the probe of wg0's endpoint +-10 min")
        print("  time            ping loss  avg ms  max ms | endpoint  probes lost  mean ms  sd ms")
        sel = data.segments[-1]["selection"]
        for p in pings:
            t = p["t_us"]
            ys = [s for s in data.samples[sel] if t - 600e6 <= s[0] < t + 600e6]
            rt = [s[2] for s in ys if s[1]]
            m = sum(rt) / len(rt) if rt else float("nan")
            sd = math.sqrt(max(sum(x * x for x in rt) / len(rt) - m * m, 0)) if rt else float("nan")
            print("  %s %9s %7s %7s | #%-7d %6d %4d %8.1f %6.1f" % (
                local_time(t, a.tz), p.get("loss", "?"), p.get("rtt_avg_ms", "?"), p.get("rtt_max_ms", "?"), sel,
                len(ys), len(ys) - len(rt), m, sd))
        print("  (the probe compares only while wg0 stays on #%d, the recorded start endpoint, in a dry-run)" % sel)


# ---------------------------------------------------------------------------
# presets, flags, objective

# History per half-life of the defaults (267 for 60): the oldest sample keeps
# 2^-4.4 = 4.6% weight. tune scales --history with --half-life by it.
HISTORY_PER_HALF_LIFE = 200 / 45

# The region worth searching (from the first router dry-run): --noise-gate
# below 2 fails the equal-path noise scenarios regardless of the data, and
# --order-bias is the list preference rather than a tunable (add it with
# --grid to explore it).
DEFAULT_GRID = {
    "half-life": [45, 60, 80, 120],
    "noise-gate": [2.0, 2.5],
    "margin": [0.10, 0.14, 0.18],
    "persist": ["30s", "45s", "90s"],
    "wait-to-restore": ["5m", "15m", "45m", "90m"],
}


def parse_indices(spec, n):
    out = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        lo, _, hi = part.partition("-")
        try:
            out += range(int(lo), int(hi or lo) + 1)
        except ValueError:
            die("bad endpoint index or range %r" % part)
    for i in out:
        if not 0 <= i < n:
            die("endpoint index %d out of range 0-%d" % (i, n - 1))
    if len(set(out)) != len(out):
        die("duplicate endpoint index in %r" % spec)
    return out


def parse_presets(specs, n):
    presets = {}
    for s in specs or ["all=0-%d" % (n - 1)]:
        name, _, spec = s.partition("=")
        if not name or not spec:
            die("--preset wants NAME=SPEC, got %r" % s)
        base, _, extra = spec.partition("+")
        idx = parse_indices(base, n)
        if not extra:
            presets[name] = sorted(idx)
            continue
        k, _, pool = extra.partition(":")
        if not k.isdigit() or not pool:
            die("--preset %s: want +K:SPEC after the base list, got +%s" % (name, extra))
        pool = [i for i in parse_indices(pool, n) if i not in idx]
        for combo in itertools.combinations(pool, int(k)):
            presets["%s+%s" % (name, ",".join(map(str, combo)))] = sorted(idx + list(combo))
    return presets


def flag_args(config):
    """{"half-life": 70, ...} to wgsteer flags; --history follows --half-life
    unless given."""
    args = []
    for k, v in config.items():
        args += ["--" + k, str(v)]
    if "half-life" in config and "history" not in config:
        args += ["--history", str(math.ceil(float(config["half-life"]) * HISTORY_PER_HALF_LIFE))]
    return args


def config_label(config):
    return " ".join("%s=%s" % (k, v) for k, v in config.items()) or "(defaults)"


def check_flags(args):
    for x in args:
        if x.lstrip("-").split("=")[0] == "probe-interval":
            die("--probe-interval is set per preset to the recorded per-endpoint period (see --help)")


class Ctx:
    """Data, presets and hindsight truth shared by replay, faults and tune."""

    def __init__(self, a):
        self.a = a
        self.data = Data(a.data)
        self.presets = parse_presets(a.preset, self.data.n)
        self.truth = Truth(self.data)
        self.evals = {name: PresetEval(self.truth, p) for name, p in self.presets.items()}
        t0, t1 = self.data.t0, self.data.t1
        self.halves = ((t0, (t0 + t1) // 2), ((t0 + t1) // 2, t1 + 1))

    def interval_us(self, preset):
        return int(round(self.data.interval_us * self.data.n / len(preset)))

    def deploy_interval(self, preset):
        return "%gs" % round(self.interval_us(preset) / 1e6, 3)

    def run(self, name, preset, args, **extra):
        r = {"name": name, "endpoints": self.presets[preset],
             "args": ["--probe-interval", "%dus" % self.interval_us(self.presets[preset])] + list(args)}
        if self.a.start is not None:
            r["start"] = self.a.start
        r.update(extra)
        return r

    def replay(self, runs, label=""):
        out = []
        for i in range(0, len(runs), 512):
            out += run_replay(self.a, self.data, runs[i:i + 512])
            if len(runs) > 512:
                print("  %s%d/%d replays" % (label, len(out), len(runs)), file=sys.stderr, flush=True)
        return out

    def metrics(self, preset, result, window=None):
        return self.evals[preset].evaluate(result, self.a.start, window)

    def objective(self, m):
        return m["pref_regret"] + self.a.switch_cost * m["switches_day"]


# ---------------------------------------------------------------------------
# replay


def metric_row(label, m):
    k = m["kinds_day"]
    return "  %-26s %6.2f %5.2f %5.2f %5.2f %5d %7.2f %7.2f %6.1f%% %6.2f%% %6.1f %5d   %s" % (
        label, m["switches_day"], k.get("degrade", 0), k.get("restore", 0), k.get("outage", 0), m["flaps"],
        m["pref_regret"], m["regret"], 100 * m["worse"], 100 * m["loss"], m["rtt"], m["outage_probes"],
        " ".join("#%d:%.0f%%" % (e, 100 * v) for e, v in m["share"].items() if v >= 0.005))


METRIC_HEADER = ("  %-26s %6s %5s %5s %5s %5s %7s %7s %7s %7s %6s %5s   %s" % (
    "", "sw/day", "degr", "rest", "outg", "flaps", "pref", "regret", "worse", "loss", "rtt", "outP", "time share"))


def cmd_replay(a):
    check_flags(a.flags)
    ctx = Ctx(a)
    runs = []
    for name in ctx.presets:
        runs.append(ctx.run(name + "/flags", name, a.flags))
        runs.append(ctx.run(name + "/defaults", name, []))
    res = ctx.replay(runs)
    print("flags: %s" % (" ".join(a.flags) or "(defaults)"))
    for k, name in enumerate(ctx.presets):
        preset = ctx.presets[name]
        mine, base = ctx.metrics(name, res[2 * k]), ctx.metrics(name, res[2 * k + 1])
        static = min(((e, ctx.evals[name].evaluate({"switches": []}, e)) for e in preset),
                     key=lambda x: x[1]["pref_regret"])
        print("\npreset %s = %s (deploy with --probe-interval %s)" % (
            name, ",".join(map(str, preset)), ctx.deploy_interval(preset)))
        print(METRIC_HEADER)
        print(metric_row("these flags", mine))
        print(metric_row("defaults", base))
        print(metric_row("static #%d (hindsight)" % static[0], static[1]))
        if a.switches:
            print("  switches (from/to: recorded index; the reason numbers endpoints by position in the preset):")
            for e in res[2 * k]["switches"]:
                print("    %s %-8s #%d -> #%d  G %s  %s" % (local_time(e["t_us"], a.tz), e["kind"], e["from"], e["to"],
                                                         e["g"] if isinstance(e["g"], str) else "%.3f" % e["g"],
                                                         e["reason"]))


# ---------------------------------------------------------------------------
# faults

# Synthetic faults: loss (probability), add_ms (RTT step), tail/tail_ms
# (share of replies delayed), dur (minutes).
FAULT_KINDS = {
    "outage": dict(loss=1.0, dur=10),
    "loss50%": dict(loss=0.5, dur=20),
    "loss30%": dict(loss=0.3, dur=30),
    "loss10%": dict(loss=0.1, dur=60),
    "+60ms": dict(add_ms=60, dur=30),
    "+30ms": dict(add_ms=30, dur=30),
    "tail30%+100ms": dict(tail=0.3, tail_ms=100, dur=30),
}


def fault_schedule(ctx, kind):
    """One fault on the then-active endpoint every --fault-every hours, the
    first 2 h into each daemon run, never across a run's end."""
    f = FAULT_KINDS[kind]
    dur = f["dur"] * 60_000_000
    out = []
    for s in ctx.data.segments:
        t = s["start_us"] + 2 * 3600_000_000
        while t + dur < s.get("end_us", s["start_us"]):
            out.append({"at_us": t, "dur_us": dur, "target": -1, "loss": f.get("loss", 0), "add_ms": f.get("add_ms", 0),
                        "tail": f.get("tail", 0), "tail_ms": f.get("tail_ms", 0)})
            t += int(ctx.a.fault_every * 3600_000_000)
    return out


def fault_runs(ctx, configs, label=""):
    """configs: list of flag lists. Returns {(config, preset, kind): [fault results]}."""
    runs, keys = [], []
    for ci, args in enumerate(configs):
        for name in ctx.presets:
            for kind in FAULT_KINDS:
                seed = int.from_bytes(("%s/%s" % (name, kind)).encode()[:8].ljust(8, b"\0"), "little") + ci
                runs.append(ctx.run("%d/%s/%s" % (ci, name, kind), name, args, seed=seed % (1 << 63),
                                    faults=fault_schedule(ctx, kind)))
                keys.append((ci, name, kind))
    return {k: r["faults"] for k, r in zip(keys, ctx.replay(runs, label))}


# A fault counts for the exposure metrics only if leaving was clearly
# warranted: the faulted endpoint's hindsight cost (the fault applied to its
# recorded mean, sd and loss) is at least WARRANT x the best other endpoint's
# of the preset, mid-fault. Otherwise staying may be right (e.g. the fault
# hit the best endpoint while the others were degraded too).
WARRANT = 1.25


def warranted(ctx, name, kind, results):
    f = FAULT_KINDS[kind]
    out = []
    for r in results:
        if r["target"] < 0:
            continue
        mid = r["at_us"] + f["dur"] * 30_000_000
        best = min(ctx.truth.cell_cost(e, mid) for e in ctx.presets[name] if e != r["target"])
        if ctx.truth.faulted_cost(r["target"], mid, f) >= WARRANT * best:
            out.append(r)
    return out


def exposure(results, kind):
    """Mean seconds on the faulted endpoint during the fault (nan: none)."""
    dur = FAULT_KINDS[kind]["dur"] * 60
    xs = [min(f["left_us"] / 1e6, dur) if f["left_us"] >= 0 else dur for f in results]
    return sum(xs) / len(xs) if xs else float("nan")


def fault_score(ctx, fr, ci, base=0):
    """(F, Fmax): warranted-fault exposure relative to config base, mean and
    max over (preset, kind) pairs where both have warranted faults."""
    rel = []
    for name in ctx.presets:
        for kind in FAULT_KINDS:
            b = exposure(warranted(ctx, name, kind, fr[(base, name, kind)]), kind)
            x = exposure(warranted(ctx, name, kind, fr[(ci, name, kind)]), kind)
            if b > 0 and x == x:
                rel.append(x / b)
    return (sum(rel) / len(rel), max(rel)) if rel else (float("nan"), float("nan"))


def cmd_faults(a):
    check_flags(a.flags)
    ctx = Ctx(a)
    fr = fault_runs(ctx, [[], a.flags])
    print("flags: %s" % (" ".join(a.flags) or "(defaults)"))
    print("Synthetic faults on the active endpoint every %g h, on top of the recorded samples. Only faults that "
          "warrant leaving count (faulted cost >= %g x the best other endpoint's). Per kind over all presets: "
          "number of such faults, time until the selection left the faulted endpoint (median / p90 / max s), "
          "share never left during the fault, mean exposure (s on it during the fault)." % (a.fault_every, WARRANT))
    print("  %-14s %4s  %-31s %-31s" % ("fault", "min", "these flags", "defaults"))
    for kind in FAULT_KINDS:
        cells = []
        for ci in (1, 0):
            res = [f for name in ctx.presets for f in warranted(ctx, name, kind, fr[(ci, name, kind)])]
            left = sorted(f["left_us"] / 1e6 for f in res if f["left_us"] >= 0)
            q = lambda p: left[min(int(p * len(left)), len(left) - 1)] if left else float("nan")
            miss = 1 - len(left) / len(res) if res else float("nan")
            cells.append("%3d: %4.0f/%4.0f/%4.0f %3.0f%% %4.0f" % (
                len(res), q(.5), q(.9), left[-1] if left else float("nan"), 100 * miss, exposure(res, kind)))
        print("  %-14s %4d  %-31s %-31s" % (kind, FAULT_KINDS[kind]["dur"], cells[0], cells[1]))
    f, fmax = fault_score(ctx, fr, 1, 0)
    print("F (exposure relative to defaults, mean over presets and kinds) = %.3f, worst %.3f" % (f, fmax))
    print("\nExposure s by preset (these flags / defaults):")
    print("  %-12s" % "" + "".join("%17s" % k for k in FAULT_KINDS))
    for name in ctx.presets:
        print("  %-12s" % name + "".join("%17s" % ("%.0f / %.0f" % tuple(
            exposure(warranted(ctx, name, k, fr[(ci, name, k)]), k) for ci in (1, 0))) for k in FAULT_KINDS))


# ---------------------------------------------------------------------------
# sim
#
# The recorded paths rarely contain lossy or near-equal conditions, so tuned
# flags are also run through the synthetic scenarios of the policy's
# behavioral targets (internal/policy TestSimParams), at the recorded
# per-endpoint period, against the targets of docs/scoring.md.

SIM_ENDPOINTS = 5  # simEndpoints in internal/policy/sim_test.go

PARAM_FIELDS = {
    "half-life": ("HalfLife", float), "history": ("History", int), "min-samples": ("MinSamples", int),
    "noise-gate": ("NoiseGate", float), "loss-weight": ("LossWeight", float),
    "jitter-weight": ("JitterWeight", float), "order-bias": ("OrderBias", float), "margin": ("Margin", float),
    "outage-epsilon": ("OutageEpsilon", float), "persist": ("Persist", None), "cooldown": ("Cooldown", None),
    "wait-to-restore": ("WaitToRestore", None), "margin-abs": ("MarginAbs", None),
}


def sim_params(args, period_us):
    """wgsteer policy flags to policy.Params JSON (durations in ns)."""
    p = {"Interval": int(period_us * 1000 / SIM_ENDPOINTS)}
    i = 0
    while i < len(args):
        name, eq, value = args[i].lstrip("-").partition("=")
        if not eq:
            if i + 1 >= len(args):
                die("flag %s has no value" % args[i])
            value = args[i + 1]
            i += 1
        i += 1
        if name == "probe-timeout":
            continue
        if name not in PARAM_FIELDS:
            die("--%s is not a policy flag" % name)
        field, conv = PARAM_FIELDS[name]
        p[field] = conv(value) if conv else go_duration_us(value) * 1000
    return p


def sim_targets(m, p, headroom=1.0):
    """Failed design targets (docs/scoring.md, behavioral targets). The rows
    that count switches on pure noise must stay within headroom x their
    target."""
    wtr = p.get("WaitToRestore", 300e9) / 1e9
    fails = []
    checks = [
        ("equal_5pct_switches_per_24h", m["equal_5pct_switches_per_24h"] <= headroom),
        ("equal_10pct_degrade_per_12h", m["equal_10pct_degrade_per_12h"] <= headroom),
        ("step_20ms_per_3h", m["step_20ms_per_3h"] <= headroom),
        ("reverts_to_worse_0", m["reverts_to_worse_0"] == 0),
        ("near_margin_switches_per_h", m["near_margin_switches_per_h"] <= 1.5),
        ("all_down_per_12h", m["all_down_per_12h"]["outage"] <= 0.25 and m["all_down_per_12h"]["all"] <= 1),
        ("restore_after_eligible_s", all(wtr <= d <= 1.5 * wtr for d in m["restore_after_eligible_s"])),
    ]
    for k in ("step_60ms", "tail_30pct_100ms", "loss_5_to_50pct", "loss_5_to_30pct", "loss_5_to_100pct"):
        checks.append((k, m[k]["missed"] == 0))
    for k, ok in checks:
        if not ok:
            fails.append(k)
    return fails


def run_sims(a, period_us, configs):
    """configs: list of flag lists; returns [(params, measurements)]."""
    binary = os.path.abspath(os.path.join(a.data, "policy.test"))
    if not getattr(a, "_sim_built", False):
        go = shutil.which("go") or die("go not found (needed to build the policy simulation)")
        subprocess.run([go, "test", "-c", "-o", binary, "./internal/policy"], cwd=REPO, check=True)
        a._sim_built = True
    params = [sim_params(c, period_us) for c in configs]
    out = []
    for i in range(0, len(params), 8):  # each run uses ~13 goroutines
        procs = [subprocess.Popen([binary, "-test.run", "^TestSimParams$", "-test.count=1"],
                                  env={**os.environ, "WGSTEER_SIM_PARAMS": json.dumps(p)},
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                 for p in params[i:i + 8]]
        for p, proc in zip(params[i:i + 8], procs):
            text = proc.communicate()[0]
            line = next((x for x in text.splitlines() if x.startswith("SIMPARAMS ")), None)
            if proc.returncode != 0 or line is None:
                die("policy simulation failed:\n" + text)
            out.append((p, json.loads(line[len("SIMPARAMS "):])))
    return out


def sim_cell(v):
    if isinstance(v, dict) and "median_s" in v:
        return "%.0f/%.0f s%s" % (v["median_s"], v["max_s"], " missed %d" % v["missed"] if v["missed"] else "")
    if isinstance(v, dict):
        return ", ".join("%s %.2f" % kv for kv in v.items())
    if isinstance(v, list):
        return "%.0f-%.0f s" % (min(v), max(v))
    return "%.2f" % v if isinstance(v, float) else str(v)


SIM_ROWS = [
    ("equal_5pct_switches_per_24h", "equal paths 5% loss: switches / 24 h", "<= 1"),
    ("equal_10pct_degrade_per_12h", "equal paths 10% loss: degrade / 12 h", "<= 1"),
    ("step_20ms_per_3h", "+20 ms on active: switches / 3 h", "<= 1"),
    ("near_margin_switches_per_h", "near-margin pair: switches / h", "<= 1.5"),
    ("reverts_to_worse_0", "restores to a worse #0", "0"),
    ("all_down_per_12h", "60 s all-down every 30 min: / 12 h", "outage <= 0.25, all <= 1"),
    ("restore_after_eligible_s", "restore after #0 eligible", "[wtr, 1.5 wtr]"),
    ("step_60ms", "+60 ms on active: median/max", "no miss"),
    ("tail_30pct_100ms", "30% of replies +100 ms: median/max", "no miss"),
    ("loss_5_to_50pct", "loss 5% -> 50%: median/max", "no miss"),
    ("loss_5_to_30pct", "loss 5% -> 30%: median/max", "no miss"),
    ("loss_5_to_100pct", "loss 5% -> 100%: median/max", "no miss"),
    ("bursty_degrade_per_12h", "bursty loss 60 s / 10 min: degrade / 12 h", "(report)"),
]


def print_sims(labels, sims):
    print("  %-42s %-26s" % ("scenario (simulation, %d endpoints)" % SIM_ENDPOINTS, "target") +
          "".join("%-24s" % l for l in labels))
    for key, title, target in SIM_ROWS:
        print("  %-42s %-26s" % (title, target) + "".join("%-24s" % sim_cell(m[key]) for _, m in sims))
    print("  %-42s %-26s" % ("failed targets", "") +
          "".join("%-24s" % (",".join(sim_targets(m, p)) or "none") for p, m in sims))


def cmd_sim(a):
    check_flags(a.flags)
    data = Data(a.data)
    period = data.interval_us * data.n if a.period is None else int(a.period * 1e6)
    print("flags: %s; per-endpoint period %g s (%s)" % (" ".join(a.flags) or "(defaults)", period / 1e6,
                                                        "the recorded one" if a.period is None else "--period"))
    print_sims(["these flags", "defaults"], run_sims(a, period, [a.flags, []]))


# ---------------------------------------------------------------------------
# tune


def cmd_tune(a):
    ctx = Ctx(a)
    grid = DEFAULT_GRID
    if a.grid:
        with open(a.grid) as f:
            grid = json.load(f)
    for k in grid:
        if k == "probe-interval":
            die("--grid: probe-interval is set per preset")
    configs = [dict(zip(grid, vs)) for vs in itertools.product(*grid.values())]
    configs = [{}] + [c for c in configs if c]  # 0: defaults
    names = list(ctx.presets)
    print("%d configs x %d presets (%s), %.1f days of samples" % (
        len(configs) - 1, len(names), ", ".join(names), (ctx.data.t1 - ctx.data.t0) / 86400e6), file=sys.stderr)

    runs = [ctx.run("%d/%s" % (ci, n), n, flag_args(c)) for ci, c in enumerate(configs) for n in names]
    res = ctx.replay(runs, "grid: ")
    rows = []
    for ci, c in enumerate(configs):
        per = {}
        for k, n in enumerate(names):
            r = res[ci * len(names) + k]
            per[n] = (ctx.metrics(n, r), ctx.metrics(n, r, ctx.halves[0]), ctx.metrics(n, r, ctx.halves[1]))
        rows.append(per)
    base = rows[0]

    def rel(per, h):
        return [ctx.objective(per[n][h]) / max(ctx.objective(base[n][h]), 1e-9) for n in names]

    table = []
    for ci, per in enumerate(rows):
        r = rel(per, 0)
        table.append({
            "ci": ci, "R": sum(r) / len(r), "Rmax": max(r), "R1": statistics.mean(rel(per, 1)),
            "R2": statistics.mean(rel(per, 2)),
            "sw": statistics.mean(per[n][0]["switches_day"] for n in names),
            "deg": statistics.mean(per[n][0]["kinds_day"].get("degrade", 0) for n in names),
            "flaps": sum(per[n][0]["flaps"] for n in names),
            "pref": statistics.mean(per[n][0]["pref_regret"] for n in names),
            "worse": statistics.mean(per[n][0]["worse"] for n in names),
        })
    ranked = sorted(table[1:], key=lambda t: t["R"])

    def show(title, ts):
        print("\n" + title)
        print("  %6s %6s %6s %6s %6s %6s %6s %6s %6s %5s %6s  %s" % (
            "R", "Rmax", "R 1st", "R 2nd", "F", "Fmax", "sw/day", "degr", "pref", "flaps", "worse", "config"))
        for t in ts:
            print("  %6.3f %6.3f %6.3f %6.3f %6s %6s %6.2f %6.2f %6.2f %5d %5.1f%%  %s" % (
                t["R"], t["Rmax"], t["R1"], t["R2"], "%.3f" % t["F"] if "F" in t else "-",
                "%.3f" % t["Fmax"] if "Fmax" in t else "-", t["sw"], t["deg"], t["pref"], t["flaps"],
                100 * t["worse"], config_label(configs[t["ci"]])))

    print("Objective J = pref regret + %g x switches/day; R = J / J(defaults) per preset, mean (Rmax: worst preset; "
          "R 1st/2nd: each half of the data). F = fault exposure relative to the defaults (lower is better)."
          % a.switch_cost)
    show("Top %d of %d configs by R:" % (min(a.top, len(ranked)), len(ranked)), [table[0]] + ranked[:a.top])

    # The half-life trades calm-data quality (long) for reaction to faults
    # (short), so each check takes the best of every half-life value;
    # otherwise the longest half-life fills it.
    def per_half_life(ts, k):
        groups = collections.defaultdict(list)
        for t in ts:
            groups[configs[t["ci"]].get("half-life")].append(t)
        return sorted((t for g in groups.values() for t in g[:k]), key=lambda t: t["R"])

    # 1. Cheap filters and the simulation targets (seconds per config).
    ok = [t for t in ranked if t["flaps"] == 0 and t["R1"] < 1 and t["R2"] < 1]
    cand = per_half_life(ok, a.sim_top)
    period = ctx.data.interval_us * ctx.data.n
    print("\nSimulation targets (noise rows at %g x their target) for the best %d per half-life with no flaps, "
          "better than the defaults on both halves: %d configs" % (a.noise_headroom, a.sim_top, len(cand)),
          file=sys.stderr)
    sims = {}
    for t, (p, m) in zip(cand, run_sims(a, period, [flag_args(configs[t["ci"]]) for t in cand])):
        t["sim_fails"] = sim_targets(m, p, a.noise_headroom)
        sims[t["ci"]] = (p, m)
    passed = [t for t in cand if not t["sim_fails"]]
    print("\nSimulation check: %d of %d configs (best %d per half-life with no flaps, better than the defaults on both "
          "halves) meet every target, noise rows at %g x their target. Failures by target: %s" % (
              len(passed), len(cand), a.sim_top, a.noise_headroom,
              ", ".join("%s %d" % kv for kv in collections.Counter(f for t in cand for f in t["sim_fails"]).most_common())
              or "none"))
    if not passed:
        return

    # 2. Fault exposure (about a minute per config).
    checked = [table[0]] + per_half_life(passed, a.fault_top)
    fr = fault_runs(ctx, [flag_args(configs[t["ci"]]) for t in checked], "faults: ")
    for k, t in enumerate(checked):
        t["F"], t["Fmax"] = fault_score(ctx, fr, k, 0)
    front = []
    for t in sorted(checked, key=lambda t: (t["R"], t["F"])):
        if not front or t["F"] < front[-1]["F"]:
            front.append(t)
    show("Pareto set over (R, F) among the %d fault-checked configs (best %d per half-life that passed the "
         "simulation):" % (len(checked) - 1, a.fault_top), front)
    final = [t for t in checked[1:] if t["F"] <= a.max_fault]
    if not final:
        print("\nNone of them has F <= %g." % a.max_fault)
        return
    pick = min(final, key=lambda t: t["R"])
    show("Pick: lowest R with no flaps, better than the defaults on both halves, every simulation target met, "
         "F <= %g:" % a.max_fault, [pick])
    print()
    print_sims(["pick", "defaults"], [sims[pick["ci"]]] + run_sims(a, period, [[]]))
    args = flag_args(configs[pick["ci"]])
    print("\nDeploy (per preset; --probe-interval keeps the recorded per-endpoint period):")
    for n in names:
        print("  %-12s wgsteer --probe-interval %s %s" % (n, ctx.deploy_interval(ctx.presets[n]), " ".join(args)))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", default="tune-data", help="extracted data directory (default: %(default)s)")
    ap.add_argument("--replay-bin", help="prebuilt cmd/wgsteer-replay (default: go build into --data)")
    ap.add_argument("--tz", type=float, help="hours east of UTC for printed times (default: local time)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    ex = sub.add_parser("extract", help="parse debug logs into --data")
    ex.add_argument("logs", nargs="+", help="log directories or files")
    sub.add_parser("verify", help="replay the recorded runs with their own flags and compare every decision")
    sub.add_parser("paths", help="per-endpoint loss/RTT, by hour of day, loss runs, common-mode losses, wg0 ground truth")

    def common(p):
        p.add_argument("--preset", action="append", metavar="NAME=SPEC",
                       help="endpoint subset, repeatable (default: all endpoints); see above")
        p.add_argument("--start", type=int, metavar="INDEX",
                       help="endpoint wg0 starts on in every daemon run (default: the recorded one)")
        p.add_argument("--switch-cost", type=float, default=1.0, metavar="MS",
                       help="objective weight of one switch per day, in ms of pref regret (default: %(default)s)")
        p.add_argument("--fault-every", type=float, default=3.0, metavar="H",
                       help="hours between synthetic faults (default: %(default)s)")

    rp = sub.add_parser("replay", help="one flag set on the presets, against the defaults")
    common(rp)
    rp.add_argument("--switches", action="store_true", help="list every switch")
    rp.add_argument("flags", nargs="*", help="wgsteer policy flags, after --")
    fp = sub.add_parser("faults", help="synthetic faults on the active endpoint, against the defaults")
    common(fp)
    fp.add_argument("flags", nargs="*", help="wgsteer policy flags, after --")
    sp = sub.add_parser("sim", help="synthetic scenarios of the policy's behavioral targets, against the defaults")
    sp.add_argument("--period", type=float, metavar="S",
                    help="per-endpoint probe period in seconds, i.e. endpoints x --probe-interval "
                         "(default: the recorded one)")
    sp.add_argument("flags", nargs="*", help="wgsteer policy flags, after --")
    tp = sub.add_parser("tune", help="grid search with fault and simulation checks")
    common(tp)
    tp.add_argument("--grid", metavar="JSON", help='{"flag": [values], ...} (default: built-in grid, see source)')
    tp.add_argument("--top", type=int, default=15, help="configs listed by R (default: %(default)s)")
    tp.add_argument("--fault-top", type=int, default=8,
                    help="best configs by R per half-life value that get the fault check (default: %(default)s)")
    tp.add_argument("--max-fault", type=float, default=1.0,
                    help="largest F (fault exposure vs defaults) for the pick (default: %(default)s)")
    tp.add_argument("--sim-top", type=int, default=16,
                    help="best configs by R per half-life value that get the simulation check (default: %(default)s)")
    tp.add_argument("--noise-headroom", type=float, default=0.5,
                    help="switches on pure noise (equal paths, +20 ms) must stay within this share of their "
                         "target (default: %(default)s)")
    a = ap.parse_args()
    {"extract": cmd_extract, "verify": cmd_verify, "paths": cmd_paths, "replay": cmd_replay, "faults": cmd_faults,
     "sim": cmd_sim, "tune": cmd_tune}[a.cmd](a)


if __name__ == "__main__":
    main()
