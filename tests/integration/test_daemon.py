"""Scenarios: the daemon in the namespace topology.

Run after `make build` (it is the last step of `make integration`):

    python3 tests/integration/test_daemon.py -v

Host requirements are those of test_topology.py. Every test builds a fresh
topology and runs its own daemon(s); the suite takes about 6 minutes.
Measured numbers are printed to stderr as "[metric] <test>: name=value
(bound ...)". A failed test prints the tail of each daemon log and keeps the
full logs in a temp directory; WGSTEER_LOG_DIR=<dir> keeps the logs of every
test.

Timing model. The daemon runs with SCALED_FLAGS (topology.py): one probe
slot is `slot`, the N listed endpoints are probed round-robin, so every
endpoint gets one sample per P = N × slot (0.4 s). --history, --half-life
and --min-samples count those samples; --persist, --cooldown and
--wait-to-restore are net times. Every bound is a formula over these values
(Timing); the formula is stated where it is used.

Paths. Every path has BASE_DELAY_MS per direction (20 ms RTT; 10-40
ms) and no loss. Degradations shape the client -> server direction ("up")
unless stated, so a round trip sees exactly the stated loss or extra delay.
"""

import ast
import ipaddress
import math
import os
import re
import signal
import sys
import tempfile
import time
import unittest
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from framework import setup_userns  # noqa: E402
from topology import (  # noqa: E402
    DEVICE,
    FWMARK,
    NFT_TABLE,
    PATH_NAMES,
    PATHS,
    SCALED_FLAGS,
    Topology,
    wait_until,
)

N = len(PATH_NAMES)
R1, R2, R3, DIRECT = (PATHS[n].endpoint for n in PATH_NAMES)
ALIAS = PATHS["relay2"].alias_endpoint
LISTED = (R1, R2, R3, DIRECT)

BASE_DELAY_MS = 10  # per direction, every path
SHIFT_MS = 60  # "+60 ms" latency shift (one way, so the RTT grows by 60 ms)
SLOW_PATH_MS = 25  # per direction: a path 2.5x slower than the others, still below the 60 ms probe timeout

# Scenarios whose degraded RTT exceeds the scaled 60 ms probe timeout (+60 ms
# shift: 80 ms; 100 ms spikes: 120 ms) run with every time flag doubled and a
# 150 ms timeout, so the probe measures a slower path instead of losses.
SLOW_FLAGS = {
    "probe-interval": "200ms",
    "probe-timeout": "150ms",
    "persist": "4s",
    "cooldown": "6s",
    "wait-to-restore": "12s",
}

SLACK = 1.0  # scheduling, reconcile/slot phase and log latency on top of a formula
OUTAGE_SLACK = 0.5
LOG_TIME_RES = 0.002  # log timestamps are truncated to ms (two of them per difference)
SETTLE = 0.05  # after a switch log line, wg0 must already be on the target
# The daemon re-reads wg0 POST_SWITCH_CHECK after a switch and re-asserts it if late old-path
# packets roamed it back; CHECK_SLACK covers the timer, the netlink read/write and log latency.
POST_SWITCH_CHECK = 0.2  # daemon postSwitchCheck
CHECK_SLACK = 0.15
DROP_SETTLE = 1.0  # late packets over the old path are gone after ~1 RTT plus the netem queue
NOT_SIGNIFICANT_S = 60  # 150 samples per endpoint: ten minutes at the default 1 s interval
IPERF_S = 32
# Spikes hit 30% of the probes: P(no spike in SPIKE_SAMPLES samples) = 0.7^26 < 1e-4.
SPIKE_SAMPLES = math.ceil(math.log(1e-4) / math.log(0.7))
OUTAGE_MAX_K = 10  # policy.OutageMaxK
REKEY_TIMEOUT = 5.333  # WireGuard handshake retry interval (5 s plus up to 1/3 s jitter)


def _seconds(v):
    v = str(v)
    if v.endswith("ms"):
        return float(v[:-2]) / 1000
    if v.endswith("s"):
        return float(v[:-1])
    raise ValueError(f"unsupported duration {v!r}")


class Timing:
    """The daemon's effective timing (SCALED_FLAGS plus overrides) and the bounds derived from it."""

    def __init__(self, flags):
        f = {**SCALED_FLAGS, **flags}
        self.slot = _seconds(f["probe-interval"])
        self.timeout = _seconds(f["probe-timeout"])
        self.history = int(f["history"])
        self.half_life = float(f["half-life"])
        self.min_samples = int(f["min-samples"])
        self.persist = _seconds(f["persist"])
        self.cooldown = _seconds(f["cooldown"])
        self.wtr = _seconds(f["wait-to-restore"])
        self.reconcile = _seconds(f.get("reconcile-interval") or "1s")  # daemon default
        self.p = N * self.slot  # sample period of one endpoint

    @property
    def eligible(self):
        """Wait limit for eligibility: min-samples cycles, one more for the first slot (sent before
        the probe has a session, so invalid), plus SLACK. On a lossy relay1 (the probe's first
        endpoint) the probe's first handshake initiation can be lost, and wireguard-go retries only
        after REKEY_TIMEOUT; probes are invalid (not losses) until then, so allow two retries."""
        return (self.min_samples + 1) * self.p + 2 * REKEY_TIMEOUT + 2 * SLACK

    def outage(self, k):
        """Outage bound: the first lost probe of the active is at most one cycle after the path
        breaks, the K-th one K-1 cycles later and recorded at its slot deadline (K×N×interval
        + slack)."""
        return k * self.p + self.timeout + OUTAGE_SLACK


def parse_record(line):
    """One slog text line -> {key: value} (quoted values unquoted), plus "t" (unix time) from time=."""
    rec = {}
    i, n = 0, len(line)
    while i < n:
        eq = line.find("=", i)
        if eq < 0:
            break
        key = line[i:eq].strip()
        j = eq + 1
        if j < n and line[j] == '"':
            k = j + 1
            while k < n and line[k] != '"':
                k += 2 if line[k] == "\\" else 1
            rec[key] = ast.literal_eval(line[j : k + 1])
            i = k + 2
        else:
            k = line.find(" ", j)
            k = n if k < 0 else k
            rec[key] = line[j:k]
            i = k + 1
    if "time" in rec:
        try:
            rec["t"] = datetime.fromisoformat(rec["time"]).timestamp()
        except ValueError:
            pass
    return rec


class Daemon:
    """A running daemon (ManagedProcess) with helpers over its parsed log records."""

    def __init__(self, proc, timing):
        self.proc = proc
        self.tm = timing

    @property
    def pid(self):
        return self.proc.pid

    def mark(self):
        return self.proc.mark()

    def signal(self, sig):
        self.proc.signal(sig)

    @staticmethod
    def _matcher(msg, where):
        token = f'msg="{msg}"' if " " in msg else f"msg={msg}"

        def match(line):
            if token not in line:
                return None
            rec = parse_record(line)
            if rec.get("msg") != msg or (where and not where(rec)):
                return None
            return rec

        return match

    def records(self, msg, since=0, where=None):
        """Records with message msg logged at index >= since (each with its line index as "_i")."""
        match = self._matcher(msg, where)
        out = []
        for i, line in enumerate(self.proc.lines(since), since):
            rec = match(line)
            if rec:
                rec["_i"] = i
                out.append(rec)
        return out

    def record(self, msg, since=0, where=None):
        recs = self.records(msg, since, where)
        if not recs:
            raise AssertionError(f"no {msg!r} record in the daemon log")
        return recs[0]

    def wait(self, msg, timeout, since=0, where=None):
        """Waits for the first record with message msg at index >= since (and where(rec))."""
        i, rec = self.proc.wait_for_line(self._matcher(msg, where), timeout, since, desc=f"{msg!r} record")
        rec["_i"] = i
        return rec

    def switch_endpoints(self, sw, timeout=2.0):
        """{endpoint: record} of the "switch record endpoint" lines following switch headline sw
        (one per listed endpoint, in list order; waits for the last, as the headline may be read
        before them)."""
        same = lambda r: r.get("switch_id") == sw["switch_id"]  # noqa: E731
        self.wait("switch record endpoint", timeout, sw["_i"], where=lambda r: same(r) and r["index"] == str(N - 1))
        return {r["endpoint"]: r for r in self.records("switch record endpoint", sw["_i"], where=same)}


def path_of(endpoint):
    return next(n for n in PATH_NAMES if PATHS[n].endpoint == endpoint)


class DaemonTestBase(unittest.TestCase):
    topo_kwargs = {}

    def setUp(self):
        self.topo = Topology(**self.topo_kwargs).build()
        self.addCleanup(self.topo.destroy)
        self.daemons = []
        result = self._outcome.result
        self._problems_before = len(result.errors) + len(result.failures)
        self.addCleanup(self._save_logs)  # runs before destroy
        for name in PATH_NAMES:
            self.topo.set_path(name, delay_ms=BASE_DELAY_MS)

    def _save_logs(self):
        # Cleanups run under a fresh outcome, so a failure is read off the result.
        result = self._outcome.result
        failed = len(result.errors) + len(result.failures) > self._problems_before
        keep = os.environ.get("WGSTEER_LOG_DIR")
        if not self.daemons or not (failed or keep):
            return
        logdir = keep or tempfile.mkdtemp(prefix="wgsteer-logs-")
        os.makedirs(logdir, exist_ok=True)
        for d in self.daemons:
            lines = d.proc.lines()
            path = os.path.join(logdir, f"{self.id()}.{d.proc.name}.log")
            with open(path, "w") as f:
                f.write("\n".join(lines) + "\n")
            if failed:
                tail = [l for l in lines if "level=DEBUG" not in l][-40:]
                print(f"\n--- {d.proc.name} log tail (full log: {path}) ---", file=sys.stderr)
                print("\n".join(tail), file=sys.stderr)

    # --- daemon

    def start(self, flags=None, name="daemon", ready=True):
        flags = dict(flags or {})
        d = Daemon(self.topo.start_daemon(flags, name=name), Timing(flags))
        self.daemons.append(d)
        if ready:
            d.wait("ready", 15)
        return d

    def wait_eligible(self, d, names=PATH_NAMES, since=0):
        """Waits for "endpoint eligible" of every named path; returns {name: record}."""
        out = {}
        for n in names:
            ep = PATHS[n].endpoint
            out[n] = d.wait("endpoint eligible", d.tm.eligible, since, where=lambda r, ep=ep: r.get("endpoint") == ep)
        return out

    def force_outage(self, d, name):
        """Blackholes path name (the selection); returns the outage switch away from it, checked against its bound."""
        mark = d.mark()
        t0 = time.time()
        self.topo.set_path(name, blackhole=True)
        sw = d.wait("switch", d.tm.outage(OUTAGE_MAX_K) + SLACK, mark)
        self.assertEqual((sw["kind"], sw["from"]), ("outage", PATHS[name].endpoint), sw)
        k = int(sw["outage_k"])
        self.assertTrue(3 <= k <= OUTAGE_MAX_K and int(sw["outage_run"]) >= k, sw)
        self.assertLessEqual(sw["t"] - t0, d.tm.outage(k), sw)
        self.metric("outage_switch_s", sw["t"] - t0, d.tm.outage(k), f"K={k}")
        return sw

    def heal(self, name):
        self.topo.set_path(name, delay_ms=BASE_DELAY_MS)

    def write_endpoints(self, lines):
        with open(self.topo.endpoints_file, "w") as f:
            f.write("".join(l + "\n" for l in lines))

    # --- assertions

    def metric(self, name, value, bound=None, note=""):
        b = f" (bound {bound:.3f})" if bound is not None else ""
        print(f"\n[metric] {self._testMethodName}: {name}={value:.3f}{b} {note}".rstrip(), file=sys.stderr)

    def assert_table(self, selection, extra=(), listed=LISTED):
        """The owned table: input hook at filter-5, wg0's listen port, denies listed − selection ∪ extra."""
        tab = self.topo.nft_table()
        self.assertIsNotNone(tab, "nft table missing")
        self.assertTrue(tab.owned, tab.flags)
        self.assertEqual(tab.progname, "wgsteer")
        self.assertEqual(tab.chains, {"input": {"type": "filter", "hook": "input", "prio": -5, "policy": "accept"}})
        self.assertEqual(tab.dports(), {self.topo.wg0().listen_port})
        self.assertEqual(tab.denied_endpoints(), (set(listed) - {selection}) | set(extra))
        for r in tab.drop_rules():
            self.assertEqual(r.family, "ip6" if ":" in r.saddr else "ip", r)
            self.assertIsNotNone(r.packets, r)
        return tab

    def assert_wg0_stays(self, endpoint, duration, interval=0.1):
        seen = []
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            seen.append(self.topo.wg0_endpoint())
            time.sleep(interval)
        self.assertEqual([e for e in seen if e != endpoint], [], f"wg0 left {endpoint}")

    def assert_traffic(self, count=10, settle=5.0):
        """wg0 passes traffic: once the first ping is answered (the server may still roam), all are."""
        t = self.topo
        wait_until(lambda: t.ping(count=1, timeout=0.5).received, timeout=settle, interval=0, desc="ping via wg0")
        r = t.ping(count=count, interval=0.05)
        self.assertEqual(r.received, count, r.output)

    def assert_verified(self, d, sw, timeout=None):
        """The switch is verified on the device with an unchanged handshake."""
        v = d.wait(
            "switch verified",
            timeout or 3 * d.tm.reconcile + SLACK,
            sw["_i"],
            where=lambda r: r.get("switch_id") == sw["switch_id"],
        )
        self.assertEqual((v["endpoint"], v["handshake_unchanged"]), (sw["to"], "true"), v)
        return v


class Scenarios:
    """Scenario table; mixed into the kernel and userspace test classes."""

    def test_adopt_at_start(self):
        """wg0 on relay1: adopted, deny-list in place, no switch while the paths are equal."""
        t = self.topo
        port = t.wg0().listen_port
        d = self.start()
        tm = d.tm
        order = ["starting", "config", "privileges", "endpoint", "device", "initial selection", "nft table", "probe", "ready"]
        idx = [d.record(m)["_i"] for m in order]
        self.assertEqual(idx, sorted(idx), "startup report order")
        # Topology.start_daemon grants exactly CAP_NET_ADMIN (the regression guard).
        self.assertEqual(d.record("privileges")["capabilities"], "cap_net_admin")
        self.assertEqual(
            [(r["index"], r["endpoint"], r["family"]) for r in d.records("endpoint")],
            [(str(i), PATHS[n].endpoint, PATHS[n].family) for i, n in enumerate(PATH_NAMES)],
        )
        dev = d.record("device")
        self.assertEqual(dev["type"], "userspace" if t.userspace else "kernel")
        self.assertEqual((dev["listen_port"], dev["endpoint"], dev["listed"]), (str(port), R1, "true"))
        init = d.record("initial selection")
        self.assertEqual((init["selection"], init["index"]), (R1, "0"))
        nft = d.record("nft table")
        self.assertEqual((nft["owner_flag"], nft["replaced_stale"], nft["listen_port"]), ("true", "false", str(port)))
        self.assertEqual(set(nft["denied"].split(",")), {R2, R3, DIRECT})
        self.assert_table(R1)
        self.wait_eligible(d)
        # Long enough for the degradation accumulator to fire twice over: 2 × (persist + cooldown).
        self.assert_wg0_stays(R1, 2 * (tm.persist + tm.cooldown))
        self.assertEqual(d.records("switch"), [])
        self.assert_traffic()

    def test_loss_degradation(self):
        """40% loss on the active path: a degradation switch to the best path within the bound."""
        t = self.topo
        # --outage-epsilon pins K at its maximum (10), so the outage rule, which a lucky run of
        # 3-5 losses can fire first at 40% loss (~20% of runs), cannot pre-empt the rule under test.
        # 40% upstream loss can drop wg0's passive keepalive; the server then hears nothing for
        # 15 s after its last data and starts a new handshake on its own, unrelated to the switch
        # but breaking the unchanged-handshake checks. A 2 s keepalive keeps the server hearing
        # from the client (all lost for 15 s: 0.4^7 ≈ 0.2%).
        t.wg_set_keepalive(2)
        d = self.start({"outage-epsilon": "1e-30"})
        tm = d.tm
        self.wait_eligible(d)
        hs = t.wg0_handshake()
        mark = d.mark()
        t0 = time.time()
        t.set_path("relay1", delay_ms=BASE_DELAY_MS, loss_pct=40, direction="up")
        # Bound: before the 40% samples fill the whole window (history × P), plus persist.
        bound = tm.history * tm.p + tm.persist + SLACK
        sw = d.wait("switch", bound + 5, mark)
        dt = sw["t"] - t0
        self.metric("loss_switch_s", dt, bound)
        self.assertEqual((sw["kind"], sw["from"]), ("degrade", R1), sw)
        self.assertIn(sw["to"], {R2, R3, DIRECT})
        self.assertGreater(float(sw["r_loss_gated"]), 0, "the loss component must drive the switch")
        self.assertGreaterEqual(float(sw["g"]), 1 + float(d.record("config")["margin"]))
        self.assertGreaterEqual(dt, tm.persist)
        self.assertLessEqual(dt, bound)
        self.assert_verified(d, sw)
        self.assertEqual(t.wg0_endpoint(), sw["to"])
        self.assertEqual(t.wg0_handshake(), hs)
        r = t.ping(count=20, interval=0.05)
        self.assertEqual(r.received, 20, r.output)

    def test_post_switch_reassert(self):
        """
        Late old-path packets can roam wg0 back right after a switch (kernel WireGuard decrypts
        asynchronously). Emulated deterministically: right after an outage switch, wg0 is put back
        on the endpoint just left (denied) by hand. The post-switch check must re-assert the target
        within ~POST_SWITCH_CHECK, long before the next regular reconcile tick (5 s here), and the
        debug trace must show that check, so a disconnected post-switch timer fails the test.
        """
        t = self.topo
        flags = {"reconcile-interval": "5s", "watchdog": "10s", "log-level": "debug"}
        d = self.start(flags)
        self.wait_eligible(d)
        sw = self.force_outage(d, "relay1")
        t.wg_set_endpoint(PATHS["relay1"])  # roamed back to the old, denied endpoint
        t_set = time.time()
        self.assertLess(t_set, sw["t"] + POST_SWITCH_CHECK, "the roam-back must precede the post-switch check")
        bound = POST_SWITCH_CHECK + CHECK_SLACK
        wait_until(lambda: t.wg0_endpoint() == sw["to"], timeout=2, interval=0.01, desc="wg0 back on the target")
        back = time.time() - sw["t"]
        self.metric("post_switch_reassert_s", back, bound)
        self.assertLessEqual(back, bound + LOG_TIME_RES)
        check = d.wait("post-switch check", 1, sw["_i"])
        ra = d.wait("re-assert", 1, check["_i"])
        self.assertEqual((ra["observed"], ra["selection"]), (PATHS["relay1"].endpoint, sw["to"]), ra)
        self.assertGreaterEqual(check["t"] - sw["t"], POST_SWITCH_CHECK - LOG_TIME_RES)
        self.assertLessEqual(ra["t"] - sw["t"], bound)
        self.assertEqual(t.wg0_endpoint(), sw["to"])
        self.assert_traffic()

    def test_external_reset(self):
        """`wg set` to the direct endpoint (netifd-like reset): re-asserted within ~1 reconcile interval."""
        t = self.topo
        d = self.start()
        tm = d.tm
        d.wait("endpoint eligible", tm.eligible)  # a few reconcile ticks in
        mark = d.mark()
        t0 = time.time()
        t.wg_set_endpoint(PATHS["direct"])
        rec = d.wait("re-assert", tm.reconcile + SLACK, mark)
        self.metric("reassert_s", rec["t"] - t0, tm.reconcile + 0.25)
        self.assertEqual((rec["observed"], rec["selection"]), (DIRECT, R1))
        self.assertLessEqual(rec["t"] - t0, tm.reconcile + 0.25)
        t.wait_wg0_endpoint(R1, timeout=1)
        self.assert_traffic()
        self.assertEqual(t.server_peer_endpoint().rsplit(":", 1)[0], PATHS["relay1"].server_sees)
        self.assertEqual(d.records("switch"), [], "a re-assert is not a switch")

    def test_ipv6(self):
        """v4 -> v6 -> v4 switches; the v6 rules work; endpoints are normalized."""
        t = self.topo
        p3 = PATHS["relay3"]
        spelled = f"[{ipaddress.IPv6Address(p3.addr).exploded.upper()}]:{p3.port}"
        self.write_endpoints([spelled if n == "relay3" else PATHS[n].endpoint for n in PATH_NAMES])
        for n in ("relay2", "direct"):  # relay3 is the best candidate when relay1 fails
            t.set_path(n, delay_ms=SLOW_PATH_MS)
        d = self.start()
        tm = d.tm
        ep = d.record("endpoint", where=lambda r: r["index"] == "2")
        self.assertEqual((ep["endpoint"], ep["family"]), (R3, "ipv6"), f"{spelled} not normalized")
        self.wait_eligible(d)
        port = t.wg0().listen_port
        rule = next(r for r in t.nft_table().drop_rules() if r.endpoint == R3)
        self.assertEqual((rule.family, rule.saddr, rule.sport, rule.dport), ("ip6", p3.addr, p3.port, port))

        sw = self.force_outage(d, "relay1")
        self.assertEqual(sw["to"], R3)
        t.wait_wg0_endpoint(R3)
        self.assert_traffic(settle=10)
        self.assertEqual(t.server_peer_endpoint().rsplit(":", 1)[0], f"[{p3.server_sees}]")
        self.assertEqual({r.family for r in self.assert_table(R3).drop_rules()}, {"ip"})

        # relay1 heals; once its outage samples age out it is not worse than relay3, and the
        # revert rule brings it back. Bound: the whole window turned over (history × P) plus
        # wait-to-restore.
        self.heal("relay1")
        t_heal = time.time()
        bound = tm.history * tm.p + tm.wtr + SLACK
        sw2 = d.wait("switch", bound, sw["_i"] + 1)
        self.metric("v6_to_v4_restore_s", sw2["t"] - t_heal, bound)
        self.assertEqual((sw2["kind"], sw2["from"], sw2["to"]), ("restore", R3, R1), sw2)
        t.wait_wg0_endpoint(R1)
        self.assert_traffic()
        self.assert_table(R1)

        # The ip6 rule drops: pushed onto relay3 from outside, wg0's next packets make the server
        # roam there; its replies over relay3 hit the rule until the daemon re-asserts relay1.
        # (Traffic must start after the push: replies still in flight over relay1 would roam wg0
        # straight back.) Retried if the re-assert lands before the first ping (~3% of attempts).
        for _ in range(3):
            mark = d.mark()
            t.wg_set_endpoint(p3)
            t.ping(count=50, interval=0.02, timeout=0.3)
            d.wait("re-assert", tm.reconcile + SLACK, mark, where=lambda r: r["observed"] == R3)
            t.wait_wg0_endpoint(R1)
            drops = t.nft_table().counters()[R3][0]
            if drops:
                break
        self.metric("ip6_rule_drops", drops)
        self.assertGreater(drops, 0)
        self.assert_traffic()

    def test_clean_stop(self):
        """SIGTERM: table removed, wg0 keeps its endpoint, exit code 0."""
        t = self.topo
        d = self.start()
        self.wait_eligible(d)
        sw = self.force_outage(d, "relay1")
        self.heal("relay1")
        t.wait_wg0_endpoint(sw["to"])
        mark = d.mark()
        d.signal(signal.SIGTERM)
        self.assertEqual(d.proc.wait(10), 0)
        self.assertEqual(t.wg0_endpoint(), sw["to"])
        for msg in ("stopping", "nft table deleted", "stopped"):
            d.record(msg, mark)
        self.assertIsNone(t.nft_table())
        self.assertNotIn(NFT_TABLE, [x["name"] for x in t.nft_tables()])
        self.assert_traffic()


class KernelDaemonTest(Scenarios, DaemonTestBase):
    def test_latency_shift(self):
        """+60 ms on the active path, no loss: degradation switch."""
        t = self.topo
        d = self.start(SLOW_FLAGS)
        tm = d.tm
        self.wait_eligible(d)
        mark = d.mark()
        t0 = time.time()
        t.set_path("relay1", delay_ms=BASE_DELAY_MS + SHIFT_MS, direction="up")
        # Bound: the first slow sample arrives within one cycle and already passes the latency gate
        # (two more cycles of slack), then persist.
        bound = tm.persist + 3 * tm.p + SLACK
        sw = d.wait("switch", bound + 5, mark)
        dt = sw["t"] - t0
        self.metric("latency_switch_s", dt, bound)
        self.assertEqual((sw["kind"], sw["from"]), ("degrade", R1), sw)
        self.assertGreater(float(sw["r_lat_gated"]), 0)
        self.assertGreaterEqual(dt, tm.persist)
        self.assertLessEqual(dt, bound)
        self.assert_verified(d, sw)
        self.assert_traffic()

    def test_jitter_routing_change(self):
        """30% of packets +100 ms on the active path (median unchanged): degradation switch."""
        t = self.topo
        d = self.start(SLOW_FLAGS)
        tm = d.tm
        self.wait_eligible(d)
        mark = d.mark()
        t0 = time.time()
        t.set_path("relay1", delay_ms=BASE_DELAY_MS, spike_ms=100, spike_pct=30, direction="up")
        # Bound: one spike in the window already passes the latency gate, so persist after the
        # first spiked sample; SPIKE_SAMPLES cycles make missing every spike a < 1e-4 event.
        bound = tm.persist + SPIKE_SAMPLES * tm.p + SLACK
        sw = d.wait("switch", bound + 5, mark)
        dt = sw["t"] - t0
        self.metric("jitter_switch_s", dt, bound)
        self.assertEqual((sw["kind"], sw["from"]), ("degrade", R1), sw)
        self.assertGreater(float(sw["r_lat_gated"]), 0, "the latency term must drive the switch")
        self.assertEqual(float(sw["r_loss_gated"]), 0, "spikes stay below the probe timeout: no loss")
        old = d.switch_endpoints(sw)[R1]
        self.assertGreater(float(old["rtt_std_ms"]), 10, old)
        self.assertGreaterEqual(dt, tm.persist)
        self.assertLessEqual(dt, bound)
        self.assert_verified(d, sw)
        self.assert_traffic()

    def test_not_significant(self):
        """Small differences (active 10% slower and 1% lossier): no switch, no flapping."""
        t = self.topo
        t.set_path("relay1", delay_ms=BASE_DELAY_MS + 1, direction="down")
        t.set_path("relay1", delay_ms=BASE_DELAY_MS + 1, loss_pct=1, direction="up")
        t.set_path("relay3", delay_ms=BASE_DELAY_MS + 1, direction="up")
        d = self.start({"summary-interval": "10s"})
        self.wait_eligible(d)
        mark = d.mark()
        self.assert_wg0_stays(R1, NOT_SIGNIFICANT_S, interval=0.5)
        self.assertEqual(d.records("switch"), [])
        # The daemon saw the difference (raw cost); only its noise-gated ratio stays below the margin.
        last = {r["endpoint"]: r for r in d.records("summary", mark)}
        self.assertGreater(float(last[R1]["cost"]), float(last[R2]["cost"]), last)

    def _revert_under_background_loss(self, loss_pct):
        """
        Active on #1 (relay2, where a failover left it), #0 (relay1) equal, loss_pct on every path:
        revert to #0 within [WTR, 1.5×WTR] after eligibility (the recovery target, whose
        simulation also starts the daemon on #1). Eligibility is the later "endpoint eligible" of
        relay1 and relay2; the revert accumulator counts the eligibility tick itself, so the lower
        bound is WTR − slot. 1 ms jitter keeps the latency terms' standard errors realistic (with
        jitter-free netem a single sub-ms scheduling outlier exceeds the 2% order bias).
        """
        t = self.topo
        for n in PATH_NAMES:
            t.set_path(n, delay_ms=BASE_DELAY_MS, jitter_ms=1, direction="down")
            t.set_path(n, delay_ms=BASE_DELAY_MS, jitter_ms=1, loss_pct=loss_pct, direction="up")
        t.wg_set_endpoint(PATHS["relay2"])
        wait_until(lambda: t.ping(count=1, timeout=0.5).received, timeout=5, interval=0, desc="ping via relay2")
        self.assertEqual(t.wg0_endpoint(), R2)
        d = self.start()
        tm = d.tm
        init = d.record("initial selection")
        self.assertEqual((init["selection"], init["index"]), (R2, "1"))
        el = self.wait_eligible(d, ("relay1", "relay2"))
        t_elig = max(r["t"] for r in el.values())
        sw = d.wait("switch", tm.eligible + 1.5 * tm.wtr + SLACK)
        dt = sw["t"] - t_elig
        self.metric("revert_after_eligibility_s", dt, 1.5 * tm.wtr, f"window [{tm.wtr - tm.slot:g}, {1.5 * tm.wtr:g}]")
        self.assertEqual((sw["kind"], sw["from"], sw["to"]), ("restore", R2, R1), sw)
        self.assertGreaterEqual(dt, tm.wtr - tm.slot - LOG_TIME_RES)
        self.assertLessEqual(dt, 1.5 * tm.wtr)
        t.wait_wg0_endpoint(R1)

    def test_revert_under_background_loss_5pct(self):
        self._revert_under_background_loss(5)

    def test_revert_under_background_loss_10pct(self):
        self._revert_under_background_loss(10)

    def test_cooldown(self):
        """Degrade the new active right after a switch: the next switch waits for the cooldown."""
        t = self.topo
        d = self.start({"log-level": "debug"})
        tm = d.tm
        self.wait_eligible(d)
        sw1 = self.force_outage(d, "relay1")
        # Its outage fires after ~K×P (3 × 0.4 s), well inside the cooldown.
        t.set_path(path_of(sw1["to"]), blackhole=True)
        sw2 = d.wait("switch", tm.cooldown + tm.outage(OUTAGE_MAX_K), sw1["_i"] + 1)
        gap = sw2["t"] - sw1["t"]
        # Bound: once the cooldown expires the outage has long fired and the target is fresh, so the
        # switch comes on one of the next ticks (one cycle of slack).
        self.metric("switch_gap_s", gap, tm.cooldown + tm.p + OUTAGE_SLACK, f"cooldown {tm.cooldown:g}")
        self.assertEqual((sw2["kind"], sw2["from"]), ("outage", sw1["to"]), sw2)
        self.assertGreaterEqual(gap, tm.cooldown - LOG_TIME_RES)
        self.assertLessEqual(gap, tm.cooldown + tm.p + OUTAGE_SLACK)
        held = [
            r
            for r in d.records("trace decision", sw1["_i"] + 1)
            if r["_i"] < sw2["_i"] and r["blocker"] == "cooldown" and "outage" in r["reason"]
        ]
        self.assertTrue(held, "no tick reported the outage held by the cooldown")

    def test_outage(self):
        """Blackhole the active path: outage switch within K×N×interval + slack."""
        t = self.topo
        d = self.start()
        self.wait_eligible(d)
        hs = t.wg0_handshake()
        sw = self.force_outage(d, "relay1")
        self.assertIn(sw["to"], {R2, R3, DIRECT})
        self.assert_verified(d, sw)
        self.assertEqual(t.wg0_endpoint(), sw["to"])
        self.assertEqual(t.wg0_handshake(), hs)
        self.assert_traffic()
        self.assert_table(sw["to"])

    def test_all_down(self):
        """Blackhole every path: no switch while down, and none when every path recovers at once."""
        t = self.topo
        d = self.start({"log-level": "debug"})
        tm = d.tm
        self.wait_eligible(d)
        mark = d.mark()
        for n in PATH_NAMES:
            t.set_path(n, blackhole=True)
        # Long enough for the longest outage run (K = 10) to complete twice.
        self.assert_wg0_stays(R1, 2 * tm.outage(OUTAGE_MAX_K))
        self.assertEqual(d.records("switch", mark), [])
        held = d.records("trace decision", mark, where=lambda r: r["blocker"] == "all-down")
        self.assertTrue(held, "no tick reported all paths down")
        # Recovery, every path at once (an uplink coming back): losses while nothing was fresh are
        # no evidence against the active, so the candidate answering first must not trigger an
        # outage switch. Watched until the active answered again, plus two cycles.
        mark = d.mark()
        for n in PATH_NAMES:
            self.heal(n)
        d.wait("trace endpoint", 2 * tm.p + SLACK, mark, where=lambda r: r["endpoint"] == R1 and r["fresh"] == "true")
        self.assert_wg0_stays(R1, 2 * tm.p)
        self.assertEqual(d.records("switch", mark), [])
        self.assert_traffic()
        self.assertEqual(d.records("switch", mark), [])

    def test_high_load_transparency(self):
        """
        iperf3 (TCP, both directions) via wg0 for IPERF_S while >= 3 switches are forced by
        alternately degrading the active path (+60 ms one way: probes exceed the 60 ms timeout and
        fail over in ~K×P while TCP keeps flowing). Asserts: after each switch wg0 stays on the
        target (sampled every 100 ms), except that late old-path packets may roam it back until
        the daemon's post-switch check, which must then re-assert it; the old path's deny counter
        rises briefly, then stops; the handshake never changes; no 1 s iperf3 interval at 0 bit/s.
        """
        t = self.topo
        d = self.start()
        tm = d.tm
        self.wait_eligible(d)
        hs = t.wg0_handshake()
        run = t.iperf3(duration=IPERF_S, interval=1, bidir=True)
        t_end = time.time() + IPERF_S
        rx0 = t.wg0_transfer()[0]
        wait_until(lambda: t.wg0_transfer()[0] > rx0 + 4_000_000, timeout=5, desc="iperf3 load")
        cursor = d.mark()
        switches, samples = [], []
        active, degraded, last_change = R1, None, 0.0
        while run.running():
            t_a = time.time()
            for rec in d.records("switch", cursor):
                switches.append(rec)
                cursor = rec["_i"] + 1
                active, last_change = rec["to"], rec["t"]
                if degraded == rec["from"]:
                    self.heal(path_of(degraded))
                    degraded = None
            if degraded is None and t_a - last_change >= tm.cooldown + 0.5 and t_a < t_end - 4:
                t.set_path(path_of(active), delay_ms=BASE_DELAY_MS + SHIFT_MS, direction="up")
                degraded = active
            ep = t.wg0_endpoint()
            tab = t.nft_table()
            samples.append((t_a, time.time(), ep, tab.counters() if tab else {}))
            time.sleep(max(0.0, t_a + 0.1 - time.time()))
        report = run.wait(timeout=15)
        switches += d.records("switch", cursor)

        self.assertGreaterEqual(len(switches), 3, [s["reason"] for s in switches])
        times = [s["t"] for s in switches]
        checked, roam_backs = 0, []
        for t_a, t_b, ep, _ in samples:
            if any(t_a - SETTLE <= x <= t_b for x in times):
                continue  # a switch happened while this sample was read
            prev = [s for s in switches if s["t"] < t_a]
            target = prev[-1]["to"] if prev else R1
            if ep != target and prev and t_a <= prev[-1]["t"] + POST_SWITCH_CHECK + CHECK_SLACK:
                roam_backs.append((prev[-1], ep))  # before the post-switch check: must be re-asserted
                continue
            self.assertEqual(ep, target, f"wg0 off target at {t_a:.3f}")
            checked += 1
        self.assertGreater(checked, IPERF_S * 5)
        for sw, ep in roam_backs:
            ra = d.records(
                "re-assert",
                sw["_i"],
                where=lambda r, sw=sw, ep=ep: r["observed"] == ep
                and r["selection"] == sw["to"]
                and r["t"] <= sw["t"] + POST_SWITCH_CHECK + CHECK_SLACK,
            )
            self.assertTrue(ra, f"switch {sw['switch_id']}: wg0 roamed back to {ep}, no prompt re-assert")
        drops = []
        for i, sw in enumerate(switches):
            nxt = times[i + 1] if i + 1 < len(times) else math.inf
            series = [(t_a, c.get(sw["from"], (0, 0))[0]) for t_a, t_b, _, c in samples if t_a > sw["t"] + SETTLE and t_b < nxt]
            late = [n for t_a, n in series if t_a >= sw["t"] + DROP_SETTLE]
            self.assertEqual(len(set(late)), min(1, len(late)), f"switch {sw['switch_id']}: drops kept rising {series}")
            drops.append(max([n for _, n in series], default=0))
            self.assert_verified(d, sw, timeout=1)
        self.assertGreater(sum(drops), 0, "no late packet hit the deny-list under load")
        self.assertEqual(t.wg0_handshake(), hs)

        ivs = [iv for iv in report["intervals"] if iv["sum"]["seconds"] >= 0.5]
        fwd = [iv["sum"]["bits_per_second"] for iv in ivs]
        rev = [iv["sum_bidir_reverse"]["bits_per_second"] for iv in ivs]
        self.assertGreater(min(fwd), 0, fwd)
        self.assertGreater(min(rev), 0, rev)
        self.metric("switches", len(switches))
        self.metric("roam_backs", len({sw["switch_id"] for sw, _ in roam_backs}), note="re-asserted by the post-switch check")
        self.metric("drops_per_switch_max", max(drops), note=f"all={drops}")
        self.metric("block_set_gap_ms_max", max(float(s["block_set_gap_ms"]) for s in switches))
        self.metric("nft_ms_max", max(float(s["nft_ms"]) for s in switches))
        self.metric("iperf_min_mbps", min(min(fwd), min(rev)) / 1e6, note=f"mean fwd {sum(fwd) / len(fwd) / 1e6:.0f}")

    def test_listen_port_change(self):
        """wg0 recreated on a new port: table rebuilt with the new dport, selection re-asserted."""
        t = self.topo
        d = self.start()
        tm = d.tm
        self.wait_eligible(d)
        sw = self.force_outage(d, "relay1")
        self.heal("relay1")
        mark = d.mark()
        port = t.recreate_wg0()  # back on its configured endpoint, relay1
        ch = d.wait("listen port changed", 3 * tm.reconcile + SLACK, mark)
        self.assertEqual(ch["new"], str(port))
        rb = d.wait("nft rebuild", tm.reconcile + SLACK, mark, where=lambda r: r["reason"] == "listen-port")
        self.assertEqual(rb["listen_port"], str(port))
        ra = d.wait("re-assert", 2 * tm.reconcile + SLACK, mark)
        self.assertEqual((ra["observed"], ra["selection"]), (R1, sw["to"]))
        t.wait_wg0_endpoint(sw["to"])
        self.assert_table(sw["to"])
        self.assert_traffic()

    def test_unlisted_alias(self):
        """relay2 replies from its alias: wg0 on the alias is not fought; switching away denies the alias and sticks."""
        t = self.topo
        t.wg_set_endpoint(PATHS["relay2"])
        self.assert_traffic()
        d = self.start()
        tm = d.tm
        self.assertEqual(d.record("initial selection")["selection"], R2)
        self.wait_eligible(d)
        mark = d.mark()
        t.set_relay2_alias(True)
        t.ping(count=3, interval=0.05)
        t.wait_wg0_endpoint(ALIAS)
        al = d.wait("alias learned", tm.reconcile + SLACK, mark)
        self.assertEqual((al["alias"], al["selection"]), (ALIAS, R2))
        self.assert_wg0_stays(ALIAS, 3 * tm.reconcile)
        self.assertEqual(d.records("re-assert", mark), [], "the alias was fought")
        self.assert_table(R2)  # the alias is not denied

        # Switch away under load (server -> client), so packets from the alias are in flight.
        run = t.iperf3(duration=8, reverse=True, interval=1)
        rx0 = t.wg0_transfer()[0]
        wait_until(lambda: t.wg0_transfer()[0] > rx0 + 4_000_000, timeout=5, desc="iperf3 load")
        mark = d.mark()
        t.set_path("relay2", delay_ms=BASE_DELAY_MS + SHIFT_MS, direction="up")  # probes time out, data flows
        sw = d.wait("switch", tm.outage(OUTAGE_MAX_K) + SLACK, mark)
        self.assertEqual(sw["from"], R2)
        self.assertIn(ALIAS, sw["denied"].split(","))
        self.assert_table(sw["to"], extra=[ALIAS])
        # The alias stays denied until the next switch, so wg0 never roams back to it.
        self.assert_wg0_stays(sw["to"], 4 * tm.reconcile + 0.5)
        drops = self.assert_table(sw["to"], extra=[ALIAS]).counters()[ALIAS][0]
        self.metric("alias_drops", drops)
        self.assertGreater(drops, 0, "no late packet from the alias reached its deny rule")
        run.wait(timeout=20)
        self.assert_traffic()

    def test_unlisted_at_start(self):
        """
        wg0 starts on relay2's alias (unlisted): every listed endpoint is denied, the alias stays
        allowed, then a startup switch to the best eligible candidate. There is no previous
        selection whose aliases the switch could retire, so the alias stays allowed. Rule 5 fires as
        soon as one candidate is eligible, which here is usually relay2 (relay1's first probe has no
        session yet, so it lags one cycle); relay2 answers from the alias, so wg0 roams there and
        the daemon learns it as relay2's alias instead of fighting it.
        """
        t = self.topo
        t.set_relay2_alias(True)
        t.wg_set_endpoint(ALIAS)
        self.assert_traffic()
        self.assertEqual(t.wg0_endpoint(), ALIAS)
        d = self.start()
        tm = d.tm
        init = d.record("initial selection")
        self.assertEqual((init["selection"], init["index"]), ("none", "-1"))
        self.assert_table(None)  # every listed endpoint denied, the alias allowed
        sw = d.wait("switch", tm.eligible + SLACK)
        self.assertEqual((sw["kind"], sw["from"]), ("startup", "none"), sw)
        recs = list(d.switch_endpoints(sw).values())
        ready = [r for r in recs if r["eligible"] == "true" and r["fresh"] == "true"]
        self.assertEqual(min(ready, key=lambda r: float(r["biased_cost"]))["endpoint"], sw["to"], recs)
        self.assertNotIn(ALIAS, sw.get("denied", "").split(","), "the startup switch retired the start endpoint")
        self.assert_verified(d, sw)
        self.assert_table(sw["to"])  # the alias stays allowed
        self.assert_traffic()
        if sw["to"] == R2:
            t.wait_wg0_endpoint(ALIAS)
            al = d.wait("alias learned", tm.reconcile + SLACK, sw["_i"])
            self.assertEqual((al["alias"], al["selection"]), (ALIAS, R2))
            self.assert_wg0_stays(ALIAS, 2 * tm.reconcile)  # relay2's alias: not fought
            self.assertEqual(d.records("re-assert"), [])
            self.assert_table(R2)

    def test_reload(self):
        """SIGHUP without the selected endpoint: immediate switch; SIGHUP adding one: it gets probed."""
        t = self.topo
        d = self.start()
        tm = d.tm
        self.wait_eligible(d)
        probe_port = int(d.record("probe")["listen_port"])
        others = [R2, R3, DIRECT]
        self.write_endpoints(others)
        mark = d.mark()
        d.signal(signal.SIGHUP)
        rl = d.wait("endpoints reloaded", 2, mark)
        self.assertIn(R1, rl["removed"])
        self.assertEqual(rl["selection_removed"], "true")
        sw = d.wait("switch", 1, mark)
        self.assertEqual((sw["kind"], sw["from"]), ("reload", R1), sw)
        self.metric("reload_switch_s", sw["t"] - rl["t"], tm.slot)
        self.assertLessEqual(sw["t"] - rl["t"], tm.slot, "not immediate")
        # The removed selection stays denied like an alias until the next switch.
        self.assert_table(sw["to"], listed=others, extra=[R1])
        t.wait_wg0_endpoint(sw["to"])
        self.assert_traffic()
        t.reset_flows("relay1")
        time.sleep(2 * tm.p)  # absence check: two full probe cycles
        self.assertNotIn(probe_port, t.flows("relay1").up, "removed endpoint still probed")

        self.write_endpoints(LISTED)
        mark = d.mark()
        d.signal(signal.SIGHUP)
        rl = d.wait("endpoints reloaded", 2, mark)
        self.assertIn(R1, rl["added"])
        wait_until(
            lambda: t.flows("relay1").up.get(probe_port, (0, 0))[0] >= 3, timeout=3 * tm.p + SLACK, desc="probes via relay1"
        )
        d.wait("endpoint eligible", tm.eligible, mark, where=lambda r: r["endpoint"] == R1)
        self.assert_table(sw["to"])

    def test_fwmark(self):
        """wg-quick style fwmark routing: the probe copies the fwmark, measures the relay paths, wg0 works."""
        t = self.topo
        t.enable_fwmark()
        relay = PATHS["relay1"]
        # Without the mark, packets to a relay route into wg0 (probes could never reach it); with it, the path.
        self.assertIn(f"dev {DEVICE}", t.client.check(["ip", "route", "get", relay.addr]))
        self.assertIn(f"dev {relay.client_if}", t.client.check(["ip", "route", "get", relay.addr, "mark", str(FWMARK)]))
        t.reset_flows()
        d = self.start()
        self.assertEqual(d.record("device")["fwmark"], str(FWMARK))
        pr = d.record("probe")
        self.assertEqual(pr["fwmark"], str(FWMARK))
        probe_port = int(pr["listen_port"])
        el = self.wait_eligible(d)
        for n in PATH_NAMES:
            fl = t.flows(n)
            self.assertGreater(fl.up.get(probe_port, (0, 0))[0], 0, f"{n}: no probe packets")
            self.assertGreater(fl.down.get(probe_port, (0, 0))[0], 0, f"{n}: no probe replies")
            self.assertTrue(20 <= float(el[n]["cost"]) < 30, el[n])  # the 20 ms path RTT, not wg0-in-wg0
        self.assert_table(R1)
        self.assert_traffic()

    def test_sigkill_and_restart(self):
        """SIGKILL: the table disappears without any restart; wg0 keeps working. Restart: one table, selection adopted."""
        t = self.topo
        d = self.start()
        self.wait_eligible(d)
        sw = self.force_outage(d, "relay1")
        self.heal("relay1")
        t.wait_wg0_endpoint(sw["to"])
        t0 = time.monotonic()
        d.proc.kill()
        self.assertEqual(d.proc.returncode, -signal.SIGKILL)
        wait_until(lambda: t.nft_table() is None, timeout=2, desc="owned table removal")
        self.metric("table_gone_s", time.monotonic() - t0)
        self.assertEqual(t.wg0_endpoint(), sw["to"])
        self.assert_traffic()

        d2 = self.start(name="daemon2")
        init = d2.record("initial selection")
        self.assertEqual(init["selection"], sw["to"])
        self.assertTrue(init["reason"].startswith("device endpoint is listed"), init)
        self.assertEqual(d2.record("nft table")["replaced_stale"], "false")
        self.assertEqual(len(d2.records("nft table")), 1)
        self.assertEqual([x for x in t.nft_tables() if x["name"] == NFT_TABLE][0]["flags"], ["owner"])
        self.assertEqual(len([x for x in t.nft_tables() if x["name"] == NFT_TABLE]), 1)
        self.assert_table(sw["to"])
        self.assertEqual(d2.records("nft reconnect"), [])

    def test_second_instance(self):
        """A second daemon on the same device refuses to start; the first keeps working."""
        t = self.topo
        d = self.start()
        tm = d.tm
        before = t.nft_table()
        handle = [x for x in t.nft_tables() if x["name"] == NFT_TABLE][0]["handle"]
        d2 = self.start(name="second", ready=False)
        self.assertEqual(d2.proc.wait(15), 1)
        fail = d2.record("startup failed")
        self.assertEqual(fail["step"], "nft")
        self.assertIn("owned by another process", fail["error"])
        self.assertEqual(t.wg0_endpoint(), R1)
        self.assertTrue(d.proc.running())
        after = self.assert_table(R1)
        self.assertEqual([x for x in t.nft_tables() if x["name"] == NFT_TABLE][0]["handle"], handle)
        self.assertEqual(after.denied_endpoints(), before.denied_endpoints())
        mark = d.mark()
        t.wg_set_endpoint(PATHS["direct"])
        d.wait("re-assert", tm.reconcile + SLACK, mark)
        t.wait_wg0_endpoint(R1)

    def test_foreign_flush(self):
        """`nft flush ruleset` and `nft -f` starting with it: both rc 0; the daemon's table and rules survive."""
        t = self.topo
        d = self.start()
        mark = d.mark()
        before = self.assert_table(R1)
        p = t.client.run(["nft", "flush", "ruleset"], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        path = os.path.join(t.workdir, "reload.nft")
        with open(path, "w") as f:
            f.write("flush ruleset\ntable inet foreign {\n\tchain c {\n\t\ttype filter hook input priority 0; policy accept;\n\t}\n}\n")
        p = t.client.run(["nft", "-f", path], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("foreign", [x["name"] for x in t.nft_tables()])
        after = self.assert_table(R1)
        self.assertEqual([(r.saddr, r.sport, r.dport) for r in after.rules], [(r.saddr, r.sport, r.dport) for r in before.rules])
        self.assertEqual(d.records("nft error", mark) + d.records("nft reconnect", mark), [])

    def test_stale_unowned_table(self):
        """A hand-made unowned table of the same name is replaced by the owned one in one transaction."""
        t = self.topo
        c = t.client
        c.check(
            ["nft", "-f", "-"],
            input=f"table inet {NFT_TABLE} {{\n\tchain input {{\n\t\ttype filter hook input priority 0; policy accept;\n"
            "\t\tudp dport 9 drop\n\t}\n}\n",
        )
        self.assertFalse(t.nft_table().owned)
        mon = t.spawn("client", ["nft", "monitor"], name="nft-monitor")

        def monitor_ready():
            c.check(["nft", "add", "table", "inet", "wgsteer_ready"])
            c.check(["nft", "delete", "table", "inet", "wgsteer_ready"])
            return any("delete table inet wgsteer_ready" in l for l in mon.lines())

        wait_until(monitor_ready, timeout=5, desc="nft monitor subscribed")
        start = mon.mark()
        d = self.start()
        nft = d.record("nft table")
        self.assertEqual((nft["replaced_stale"], nft["owner_flag"]), ("true", "true"))
        tab = self.assert_table(R1)
        self.assertNotIn(9, tab.dports())
        mon.wait_for_log(rf"^add rule inet {NFT_TABLE} input .* drop$", timeout=5, since=start)
        events = mon.lines(start)
        self.assertIn(f"delete table inet {NFT_TABLE}", events)
        i_del = events.index(f"delete table inet {NFT_TABLE}")
        i_gen = next((i for i in range(i_del, len(events)) if events[i].startswith("# new generation")), None)
        self.assertIsNotNone(i_gen, events)
        # The stale table's deletion, the owned table and its chain commit together (the deny rules
        # follow in the first Apply): no window without a table of that name.
        txn = events[i_del : i_gen + 1]
        self.assertRegex(txn[-1], r"^# new generation \d+ by process \d+ \(wgsteer\)$", events)
        self.assertTrue(any(re.match(rf"(create|add) table inet {NFT_TABLE}\b", l) for l in txn), events)
        self.assertTrue(any(l.startswith(f"add chain inet {NFT_TABLE} input") for l in txn), events)

    def test_dry_run(self):
        """--dry-run: degrading the active logs "would switch"; no table; wg0 untouched."""
        t = self.topo
        d = self.start({"dry-run": True})
        self.assertEqual(d.record("nft table skipped")["reason"], "dry-run")
        self.assertIsNone(t.nft_table())
        self.wait_eligible(d)
        peer = t.wg0_peer()
        mark = d.mark()
        t.set_path("relay1", blackhole=True)
        sw = d.wait("would switch", d.tm.outage(OUTAGE_MAX_K) + SLACK, mark)
        self.assertEqual((sw["kind"], sw["from"]), ("outage", R1), sw)
        self.assert_wg0_stays(R1, 3 * d.tm.reconcile)
        after = t.wg0_peer()
        self.assertEqual((after.endpoint, after.keepalive), (peer.endpoint, peer.keepalive))
        self.assertEqual(d.records("switch"), [])
        self.assertIsNone(t.nft_table())


class UserspaceDaemonTest(DaemonTestBase):
    """A subset with wg0 as wireguard-go, covering wgctrl's userspace (UAPI socket) path."""

    topo_kwargs = {"userspace": True}
    test_adopt_at_start = Scenarios.test_adopt_at_start
    test_loss_degradation = Scenarios.test_loss_degradation
    test_external_reset = Scenarios.test_external_reset
    test_ipv6 = Scenarios.test_ipv6
    test_clean_stop = Scenarios.test_clean_stop


if __name__ == "__main__":
    setup_userns()
    unittest.main()
