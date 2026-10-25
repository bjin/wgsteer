"""The topology: one WireGuard client, three relays and a direct path
to one WireGuard server, each path shaped independently with netem.

    client ── c-r1 ═ r1-c [relay1 v4]          r1-s ═ s-r1 ── server
           ── c-r2 ═ r2-c [relay2 v4 + alias]  r2-s ═ s-r2 ──
           ── c-r3 ═ r3-c [relay3 v6]          r3-s ═ s-r3 ──
           ── c-dir ═══════════════════════════════ s-dir ───

Relays DNAT `relay addr:port` to the server's address on their server-side
link (port 51820) and masquerade, so the server sees a distinct source per
path and roams (roaming on, the WireGuard default). Each path has a netem
qdisc per direction (`set_path`). All addresses are configurable through the
environment (WGSTEER_V4_PREFIX, WGSTEER_V6_PREFIX, WGSTEER_TUNNEL_PREFIX,
WGSTEER_SERVER_PORT, WGSTEER_RELAY_PORT_BASE); everything lives in private network
namespaces, so overrides only matter for readability or odd host setups.
"""

import atexit
import base64
import ipaddress
import json
import os
import random
import re
import shutil
import signal
import statistics
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from framework import CommandError, ManagedProcess, NetNS

REPO_ROOT = Path(__file__).resolve().parents[2]

V4_PREFIX = os.environ.get("WGSTEER_V4_PREFIX", "10.231")  # underlay: <prefix>.<link>.<host>/24
V6_PREFIX = os.environ.get("WGSTEER_V6_PREFIX", "fd00:231")  # underlay: <prefix>:<link>::<host>/64
TUNNEL_PREFIX = os.environ.get("WGSTEER_TUNNEL_PREFIX", "192.0.2")
SERVER_PORT = int(os.environ.get("WGSTEER_SERVER_PORT", "51820"))
RELAY_PORT_BASE = int(os.environ.get("WGSTEER_RELAY_PORT_BASE", "40000"))  # relay i listens on base+i

SERVER_TUNNEL_ADDR = f"{TUNNEL_PREFIX}.1"  # server wg0, ICMP target (--target)
CLIENT_TUNNEL_ADDR = f"{TUNNEL_PREFIX}.2"  # client wg0
PROBE_TUNNEL_ADDR = f"{TUNNEL_PREFIX}.3"  # the daemon's in-process probe (--probe-addr); on no interface
TUNNEL_PREFIXLEN = 24

DEVICE = "wg0"
NFT_TABLE = f"wgsteer_{DEVICE}"  # the daemon's default --nft-table
FWMARK = 51820  # wg-quick style fwmark and routing table
IPERF_PORT = 5201

DAEMON_BIN = Path(os.environ.get("WGSTEER_BIN", REPO_ROOT / "wgsteer"))

# Regression guard: every daemon runs with exactly CAP_NET_ADMIN, the only
# capability wgsteer needs (docs/design.md, Privileges). It stays uid 0 of
# the user namespace, but noroot securebits make that uid carry no
# capabilities of its own; the kernel's netlink, nftables and SO_MARK checks
# look only at capabilities, so this behaves like a non-root service user.
DAEMON_PRIVILEGES = (
    "setpriv",
    "--inh-caps=-all,+net_admin",
    "--ambient-caps=-all,+net_admin",
    "--bounding-set=-all,+net_admin",
    "--securebits=+noroot,+noroot_locked,+no_setuid_fixup,+no_setuid_fixup_locked",
    "--no-new-privs",
)

# Scaled daemon tunables. start_daemon() passes
# these unless overridden; a value of None drops the flag.
#
# With 4 endpoints every endpoint gets one sample per 4 × 100 ms = 0.4 s.
# Sample counts shrink with the window: history 50 and half-life 15 keep a
# window of a few half-lives like the defaults (267/60), min-samples 10 is
# two thirds of a half-life (defaults: 20 of 60). margin-abs scales
# with the cost level: harness paths cost ~20 ms where the defaults assume
# ~150-200 ms, so 10 ms would demand a 50% effect and block every
# degradation switch; 2 ms keeps it a minor floor below --margin, as in
# production. --watchdog must be at least twice the default 1 s reconcile
# interval.
SCALED_FLAGS = {
    "probe-interval": "100ms",
    "probe-timeout": "60ms",
    "history": "50",
    "half-life": "15",
    "min-samples": "10",
    "margin-abs": "2ms",
    "persist": "2s",
    "cooldown": "3s",
    "wait-to-restore": "6s",
    "watchdog": "2s",
}

PATH_NAMES = ("relay1", "relay2", "relay3", "direct")  # also the endpoint-file order


def fmt_endpoint(addr, port):
    """Formats addr:port the way `wg show` prints it ([v6]:port, compressed, lower case)."""
    a = ipaddress.ip_address(addr)
    return f"[{a.compressed}]:{port}" if a.version == 6 else f"{a}:{port}"


def wait_until(fn, timeout=10.0, interval=0.05, desc="condition"):
    """Polls fn() until it returns a truthy value (returned); raises TimeoutError."""
    deadline = time.monotonic() + timeout
    while True:
        v = fn()
        if v:
            return v
        if time.monotonic() >= deadline:
            raise TimeoutError(f"timed out after {timeout}s waiting for {desc}")
        time.sleep(interval)


@dataclass(frozen=True)
class PathSpec:
    """One candidate path. `endpoint` is what wg0 and the endpoint file use."""

    name: str
    index: int  # position in the endpoint file
    addr: str  # client-facing address of the relay (or the server for "direct")
    port: int
    client_if: str  # veth in the client namespace
    relay: str | None  # relay namespace name, None for "direct"
    upstream_if: tuple  # (namespace name, ifname) whose egress shapes client -> server
    downstream_if: tuple  # (namespace name, ifname) whose egress shapes server -> client
    alias: str | None = None  # relay2's second address
    server_sees: str = ""  # source address of this path's packets at the server (relay masquerade / client direct)

    @property
    def family(self):
        return "ipv6" if ":" in self.addr else "ipv4"

    @property
    def endpoint(self):
        return fmt_endpoint(self.addr, self.port)

    @property
    def alias_endpoint(self):
        return fmt_endpoint(self.alias, self.port) if self.alias else None


def _v4(link, host):
    return f"{V4_PREFIX}.{link}.{host}"


def _v6(link, host):
    return str(ipaddress.ip_address(f"{V6_PREFIX}:{link}::{host}"))


def _build_paths():
    paths = {}
    for i in (1, 2, 3):
        name = f"relay{i}"
        addr = _v6(i, 1) if i == 3 else _v4(i, 1)
        paths[name] = PathSpec(
            name=name,
            index=i - 1,
            addr=addr,
            port=RELAY_PORT_BASE + i,
            client_if=f"c-r{i}",
            relay=name,
            upstream_if=(name, f"r{i}-s"),
            downstream_if=(name, f"r{i}-c"),
            alias=_v4(2, 11) if i == 2 else None,
            server_sees=_v6(13, 1) if i == 3 else _v4(10 + i, 1),
        )
    paths["direct"] = PathSpec(
        name="direct",
        index=3,
        addr=_v4(0, 1),
        port=SERVER_PORT,
        client_if="c-dir",
        relay=None,
        upstream_if=("client", "c-dir"),
        downstream_if=("server", "s-dir"),
        server_sees=_v4(0, 2),
    )
    return paths


PATHS = _build_paths()


# ---------------------------------------------------------------- wg helpers


def b64_to_hex(key):
    return base64.b64decode(key).hex()


@dataclass
class WGPeer:
    public_key: str
    endpoint: str | None
    allowed_ips: list
    latest_handshake: int  # unix seconds, 0 = never
    rx: int
    tx: int
    keepalive: int  # 0 = off


@dataclass
class WGDevice:
    public_key: str
    listen_port: int
    fwmark: int  # 0 = off
    peers: dict  # public key (base64) -> WGPeer


def parse_wg_dump(text):
    lines = [l.split("\t") for l in text.strip().splitlines()]
    priv, pub, port, mark = lines[0]
    peers = {}
    for f in lines[1:]:
        peers[f[0]] = WGPeer(
            public_key=f[0],
            endpoint=None if f[2] == "(none)" else f[2],
            allowed_ips=[] if f[3] == "(none)" else f[3].split(","),
            latest_handshake=int(f[4]),
            rx=int(f[5]),
            tx=int(f[6]),
            keepalive=0 if f[7] == "off" else int(f[7]),
        )
    return WGDevice(public_key=pub, listen_port=int(port), fwmark=0 if mark == "off" else int(mark, 0), peers=peers)


# --------------------------------------------------------------- nft helpers


@dataclass
class NftRule:
    chain: str
    handle: int
    family: str | None  # "ip" / "ip6" from the saddr match (or meta nfproto)
    saddr: str | None
    sport: int | None
    dport: int | None
    packets: int | None
    bytes: int | None
    verdict: str | None  # "drop", "accept", ...
    expr: list = field(repr=False, default_factory=list)

    @property
    def endpoint(self):
        """The denied source as an endpoint string (matches PathSpec.endpoint)."""
        if self.saddr is None or self.sport is None:
            return None
        return fmt_endpoint(self.saddr, self.sport)


@dataclass
class NftTable:
    family: str
    name: str
    flags: list
    chains: dict  # name -> {"type","hook","prio","policy"}
    rules: list  # NftRule
    text: str = field(repr=False, default="")

    @property
    def owned(self):
        return "owner" in self.flags

    @property
    def progname(self):
        """Owner process name from `nft list table` (`# progname X`), if owned."""
        m = re.search(r"# progname (\S+)", self.text)
        return m.group(1) if m else None

    def drop_rules(self, chain=None):
        return [r for r in self.rules if r.verdict == "drop" and (chain is None or r.chain == chain)]

    def denied_endpoints(self):
        return {r.endpoint for r in self.drop_rules() if r.endpoint}

    def dports(self):
        return {r.dport for r in self.drop_rules()}

    def counters(self):
        """denied endpoint -> (packets, bytes)."""
        return {r.endpoint: (r.packets or 0, r.bytes or 0) for r in self.drop_rules() if r.endpoint}


def _int(v):
    if isinstance(v, int):
        return v
    return int(str(v), 0)


def parse_nft_rule(r):
    rule = NftRule(r["chain"], r["handle"], None, None, None, None, None, None, None, r["expr"])
    for e in r["expr"]:
        if "match" in e:
            left, right = e["match"]["left"], e["match"]["right"]
            if "meta" in left and left["meta"].get("key") == "nfproto":
                rule.family = {"ipv4": "ip", "ipv6": "ip6"}.get(right, rule.family)
            elif "payload" in left:
                p = left["payload"]
                proto, fld = p.get("protocol"), p.get("field")
                if proto in ("ip", "ip6") and fld == "saddr":
                    rule.family, rule.saddr = proto, str(ipaddress.ip_address(right))
                elif proto in ("udp", "th") and fld in ("sport", "dport"):
                    setattr(rule, fld, _int(right))
                elif p.get("base") == "th" and p.get("len") == 16 and p.get("offset") in (0, 16):
                    setattr(rule, "sport" if p["offset"] == 0 else "dport", _int(right))
                elif p.get("base") == "nh" and (p.get("offset"), p.get("len")) == (96, 32):
                    rule.family, rule.saddr = "ip", str(ipaddress.IPv4Address(_int(right)))
                elif p.get("base") == "nh" and (p.get("offset"), p.get("len")) == (64, 128):
                    rule.family, rule.saddr = "ip6", str(ipaddress.IPv6Address(_int(right)))
        elif "counter" in e and e["counter"] is not None:
            rule.packets, rule.bytes = e["counter"].get("packets"), e["counter"].get("bytes")
        else:
            for v in ("drop", "accept", "reject", "return", "jump", "goto", "continue"):
                if v in e:
                    rule.verdict = v
    return rule


def nft_tables(ns):
    """`nft -j list tables` -> [{"family","name","handle","flags"}] (flags e.g. ["owner"])."""
    out = json.loads(ns.check(["nft", "-j", "list", "tables"]))
    return [
        {"family": t["family"], "name": t["name"], "handle": t["handle"], "flags": t.get("flags", [])}
        for t in (o["table"] for o in out["nftables"] if "table" in o)
    ]


def nft_table(ns, name=NFT_TABLE, family="inet"):
    """Parsed table, or None when it does not exist."""
    p = ns.run(["nft", "-j", "list", "table", family, name], capture_output=True, text=True)
    if p.returncode != 0:
        if "No such file or directory" in p.stderr:
            return None
        raise CommandError(f"nft list table {family} {name}: {p.stderr.strip()}")
    objs = json.loads(p.stdout)["nftables"]
    t = next(o["table"] for o in objs if "table" in o)
    chains = {
        c["name"]: {k: c.get(k) for k in ("type", "hook", "prio", "policy")}
        for c in (o["chain"] for o in objs if "chain" in o)
    }
    rules = [parse_nft_rule(o["rule"]) for o in objs if "rule" in o]
    text = ns.run(["nft", "list", "table", family, name], capture_output=True, text=True).stdout
    return NftTable(family, name, t.get("flags", []), chains, rules, text)


# ------------------------------------------------------- tc distributions


_NETEM_DIST_SCALE = 8192
_DIST_SIZE = 4096

# Where this host's tc reads netem distribution tables. iproute2 7.2 on Arch
# hardcodes /usr/share/tc (TC_LIB_DIR only affects plugins); other builds use
# /usr/lib/tc. Every node bind-mounts its own table directory over it.
TC_DIST_DIR = os.environ.get("WGSTEER_TC_DIST_DIR") or next(
    (d for d in ("/usr/share/tc", "/usr/lib/tc", "/usr/lib64/tc") if os.path.isdir(d)), None
)


def _write_dist(path, values):
    with open(path, "w") as f:
        f.write("# generated by tests/integration/topology.py\n")
        for i in range(0, len(values), 8):
            f.write(" ".join(str(v) for v in values[i : i + 8]) + "\n")


def _prepare_tc_lib(dirpath):
    """
    Builds the node-private distribution directory: the stock tables (or a
    generated normal table) plus "uniform", so that every jittered netem
    config sends an explicit table (netem keeps the old table when a change
    omits one), and room for generated spike tables.
    """
    if TC_DIST_DIR is None:
        raise RuntimeError("no tc distribution directory found; set WGSTEER_TC_DIST_DIR")
    os.makedirs(dirpath, exist_ok=True)
    for fn in os.listdir(TC_DIST_DIR):
        if fn.endswith(".dist"):
            shutil.copy(os.path.join(TC_DIST_DIR, fn), dirpath)
    if not os.path.exists(os.path.join(dirpath, "normal.dist")):
        nd = statistics.NormalDist()
        vals = [round(nd.inv_cdf((i + 0.5) / _DIST_SIZE) * _NETEM_DIST_SCALE) for i in range(_DIST_SIZE)]
        _write_dist(os.path.join(dirpath, "normal.dist"), [max(-32768, min(32767, v)) for v in vals])
    _write_dist(
        os.path.join(dirpath, "uniform.dist"),
        [round(-_NETEM_DIST_SCALE + 2 * _NETEM_DIST_SCALE * (i + 0.5) / _DIST_SIZE) for i in range(_DIST_SIZE)],
    )


def _spike_dist(dirpath, pct):
    """Two-point table: pct% of packets get +1 sigma (the spike), the rest +0."""
    name = f"spike{pct:g}".replace(".", "_")
    path = os.path.join(dirpath, name + ".dist")
    if not os.path.exists(path):
        n = 1000
        k = round(n * pct / 100)
        _write_dist(path, [_NETEM_DIST_SCALE] * k + [0] * (n - k))
    return name


# ----------------------------------------------------------- wireguard-go

_wggo_path = None


def wireguard_go_binary():
    """
    Path to a wireguard-go binary built from the module pinned in go.mod
    (`go build golang.zx2c4.com/wireguard` in the repo root, offline). Built
    once per test process; WGSTEER_WIREGUARD_GO overrides it. Raises if the
    build would touch go.mod/go.sum.
    """
    global _wggo_path
    if os.environ.get("WGSTEER_WIREGUARD_GO"):
        return os.environ["WGSTEER_WIREGUARD_GO"]
    if _wggo_path:
        return _wggo_path
    d = tempfile.mkdtemp(prefix="wgsteer-wggo-")
    atexit.register(shutil.rmtree, d, True)
    out = os.path.join(d, "wireguard-go")
    before = [(REPO_ROOT / f).read_bytes() for f in ("go.mod", "go.sum")]
    env = dict(os.environ, GOPROXY="off", GOFLAGS="-mod=readonly", CGO_ENABLED="0")
    p = subprocess.run(
        ["go", "build", "-o", out, "golang.zx2c4.com/wireguard"], cwd=REPO_ROOT, env=env, capture_output=True, text=True
    )
    after = [(REPO_ROOT / f).read_bytes() for f in ("go.mod", "go.sum")]
    if before != after:
        raise RuntimeError("building wireguard-go modified go.mod/go.sum")
    if p.returncode != 0:
        raise RuntimeError(f"go build golang.zx2c4.com/wireguard failed: {p.stderr.strip()}")
    _wggo_path = out
    return out


# ------------------------------------------------------------ result types


@dataclass
class PingResult:
    sent: int
    rtts: dict  # icmp_seq -> rtt ms
    output: str = field(repr=False, default="")

    @property
    def received(self):
        return len(self.rtts)

    @property
    def loss(self):
        return 1 - self.received / self.sent if self.sent else 0.0

    @property
    def rtt_list(self):
        return [self.rtts[k] for k in sorted(self.rtts)]


@dataclass
class Flows:
    """Per-path UDP packet counters keyed by the client's port (before any NAT).

    up:   client -> path, keyed by the client's source port
    down: path -> client, keyed by the client's destination port
    Values are (packets, bytes).
    """

    up: dict
    down: dict


class Iperf3Run:
    """A running `iperf3 -c` in the client namespace; wait() returns the parsed -J report."""

    def __init__(self, proc):
        self.proc = proc
        self._report = None

    def running(self):
        return self.proc.running()

    def wait(self, timeout=None):
        rc = self.proc.wait(timeout)
        out = self.proc.output()
        start = out.find("{")
        if start < 0:
            raise RuntimeError(f"iperf3 rc={rc}, no JSON report:\n{out}")
        self._report = json.loads(out[start:])
        if rc != 0 or "error" in self._report:
            raise RuntimeError(f"iperf3 rc={rc}: {self._report.get('error')}")
        return self._report

    def intervals_bps(self):
        """bits/s per reporting interval (after wait())."""
        return [iv["sum"]["bits_per_second"] for iv in self._report["intervals"]]

    def stop(self):
        return self.proc.stop(signal.SIGINT)


# ------------------------------------------------------------------ topology


@dataclass
class Keys:
    client_priv: str
    client_pub: str
    server_priv: str
    server_pub: str
    probe_priv: str
    probe_pub: str


class Topology:
    """
    Builds and owns the whole topology. Use as a context manager or call
    build()/destroy(). Namespaces: client (private /run, wg0 + daemon),
    relay1, relay2, relay3, server. See the module docstring.

    Generated files (in self.workdir, a fresh temp dir):
      probe.conf      probe identity, UAPI hex format (--probe-config)
      endpoints       relay1, relay2, [v6] relay3, direct (--endpoints)
      client.key / server.key  base64 private keys (wg set private-key)
      tc/             netem distribution tables, bind-mounted over TC_DIST_DIR in every node
    """

    def __init__(self, userspace=False, keepalive=25, initial="relay1", listen_port=None, fwmark=False):
        """
        userspace: client wg0 is wireguard-go instead of kernel WireGuard.
        keepalive: wg0's persistent keepalive (0 = off).
        initial: wg0's "configured" endpoint: a path name or an endpoint
          string (e.g. PATHS["relay2"].alias_endpoint); recreate_wg0() reuses it.
        listen_port: wg0's initial listen port (None = random).
        fwmark: apply enable_fwmark() during build.
        """
        self.userspace = userspace
        self.keepalive = keepalive
        self.initial_endpoint = PATHS[initial].endpoint if initial in PATHS else initial
        self.initial_listen_port = listen_port
        self.paths = PATHS
        self.ns = {}
        self.client = self.server = None
        self.workdir = None
        self.keys = None
        self.fwmark_enabled = False
        self._want_fwmark = fwmark
        self._procs = []
        self._wggo = None
        self.iperf_server = None

    # --- lifecycle

    def __enter__(self):
        self.build()
        return self

    def __exit__(self, *exc):
        self.destroy()

    def build(self, handshake=True):
        try:
            self._build(handshake)
        except BaseException:
            self.destroy()
            raise
        return self

    def _build(self, handshake):
        self.workdir = tempfile.mkdtemp(prefix="wgsteer-it-")
        self.tc_lib_dir = os.path.join(self.workdir, "tc")
        _prepare_tc_lib(self.tc_lib_dir)
        binds = {TC_DIST_DIR: self.tc_lib_dir}
        self.client = self.ns["client"] = NetNS("client", private_run=True, binds=binds)
        for r in ("relay1", "relay2", "relay3"):
            self.ns[r] = NetNS(r, binds=binds)
        self.server = self.ns["server"] = NetNS("server", binds=binds)
        self.keys = self._gen_keys()
        self.client_key_file = self._write("client.key", self.keys.client_priv + "\n", 0o600)
        self.server_key_file = self._write("server.key", self.keys.server_priv + "\n", 0o600)
        self.probe_config = self._write(
            "probe.conf",
            f"private_key={b64_to_hex(self.keys.probe_priv)}\n"
            f"public_key={b64_to_hex(self.keys.server_pub)}\n"
            f"allowed_ip={SERVER_TUNNEL_ADDR}/32\n",
            0o600,
        )
        self.endpoints_file = self._write("endpoints", "".join(PATHS[n].endpoint + "\n" for n in PATH_NAMES))

        self._links()
        self._relays()
        self._server()
        self._shaping()
        self._warm_neighbors()
        self._create_wg0(self.initial_listen_port, self.initial_endpoint)
        if self._want_fwmark:
            self.enable_fwmark()
        if handshake:
            wait_until(lambda: self.ping(count=1, timeout=1).received, timeout=10, interval=0, desc="first ping via wg0")

    def destroy(self):
        for p in reversed(self._procs):
            try:
                p.stop(timeout=3)
            except Exception:
                pass
        self._procs.clear()
        for ns in self.ns.values():
            ns.cleanup()
        self.ns.clear()
        if self.workdir:
            shutil.rmtree(self.workdir, ignore_errors=True)
            self.workdir = None

    # --- setup helpers

    def _write(self, name, content, mode=0o644):
        path = os.path.join(self.workdir, name)
        with open(path, "w") as f:
            f.write(content)
        os.chmod(path, mode)
        return path

    def _gen_keys(self):
        def pair():
            priv = subprocess.run(["wg", "genkey"], check=True, capture_output=True, text=True).stdout.strip()
            pub = subprocess.run(["wg", "pubkey"], input=priv, check=True, capture_output=True, text=True).stdout.strip()
            return priv, pub

        return Keys(*pair(), *pair(), *pair())

    def _ip_batch(self, ns, cmds):
        ns.check(["ip", "-batch", "-"], input="\n".join(cmds) + "\n")

    def _sysctl(self, ns, *settings):
        ns.check(["sysctl", "-qw", *settings])

    def _links(self):
        c, s = self.client, self.server
        ccmds, scmds = ["link set lo up"], ["link set lo up"]
        for i in (1, 2, 3):
            r = self.ns[f"relay{i}"]
            ccmds.append(f"link add c-r{i} type veth peer name r{i}-c netns {r.pid}")
            scmds.append(f"link add s-r{i} type veth peer name r{i}-s netns {r.pid}")
        ccmds.append(f"link add c-dir type veth peer name s-dir netns {s.pid}")
        self._ip_batch(c, ccmds)
        self._ip_batch(s, scmds)

        for i in (1, 2, 3):
            r = self.ns[f"relay{i}"]
            if i == 3:
                cl, rc, rs, sv = _v6(3, 2), _v6(3, 1), _v6(13, 1), _v6(13, 2)
                pl, extra = 64, " nodad"
            else:
                cl, rc, rs, sv = _v4(i, 2), _v4(i, 1), _v4(10 + i, 1), _v4(10 + i, 2)
                pl, extra = 24, ""
            ccmds = [f"addr add {cl}/{pl} dev c-r{i}{extra}", f"link set c-r{i} up"]
            self._ip_batch(c, ccmds)
            rcmds = [
                "link set lo up",
                f"addr add {rc}/{pl} dev r{i}-c{extra}",
                f"addr add {rs}/{pl} dev r{i}-s{extra}",
                f"link set r{i}-c up",
                f"link set r{i}-s up",
            ]
            if PATHS[f"relay{i}"].alias:
                rcmds.append(f"addr add {PATHS[f'relay{i}'].alias}/24 dev r{i}-c")
            self._ip_batch(r, rcmds)
            self._ip_batch(s, [f"addr add {sv}/{pl} dev s-r{i}{extra}", f"link set s-r{i} up"])
            if i == 3:
                self._sysctl(r, "net.ipv6.conf.all.forwarding=1")
            else:
                self._sysctl(r, "net.ipv4.ip_forward=1")
        self._ip_batch(c, [f"addr add {_v4(0, 2)}/24 dev c-dir", "link set c-dir up"])
        self._ip_batch(s, [f"addr add {_v4(0, 1)}/24 dev s-dir", "link set s-dir up"])

    @staticmethod
    def _counter_sets():
        return """
	set flows_up {
		type inet_service
		flags dynamic
		counter
	}
	set flows_down {
		type inet_service
		flags dynamic
		counter
	}"""

    def _relays(self):
        for i in (1, 2, 3):
            p = PATHS[f"relay{i}"]
            if i == 3:
                dnat = f"dnat ip6 to [{_v6(13, 2)}]:{SERVER_PORT}"
            else:
                dnat = f"dnat ip to {_v4(10 + i, 2)}:{SERVER_PORT}"
            cif, sif = f"r{i}-c", f"r{i}-s"
            self.ns[p.relay].check(
                ["nft", "-f", "-"],
                input=f"""table inet harness {{{self._counter_sets()}
	chain count_in {{
		type filter hook prerouting priority -300; policy accept;
		iifname "{cif}" udp dport {p.port} update @flows_up {{ udp sport }}
	}}
	chain nat_pre {{
		type nat hook prerouting priority dstnat; policy accept;
		iifname "{cif}" udp dport {p.port} {dnat}
	}}
	chain nat_post {{
		type nat hook postrouting priority srcnat; policy accept;
		oifname "{sif}" masquerade
	}}
	chain count_out {{
		type filter hook postrouting priority 300; policy accept;
		oifname "{cif}" udp sport {p.port} update @flows_down {{ udp dport }}
	}}
}}
""",
            )

    def _server(self):
        s, k = self.server, self.keys
        s.check(
            ["nft", "-f", "-"],
            input=f"""table inet harness {{{self._counter_sets()}
	chain count_in {{
		type filter hook prerouting priority -300; policy accept;
		iifname "s-dir" udp dport {SERVER_PORT} update @flows_up {{ udp sport }}
	}}
	chain count_out {{
		type filter hook postrouting priority 300; policy accept;
		oifname "s-dir" udp sport {SERVER_PORT} update @flows_down {{ udp dport }}
	}}
}}
""",
        )
        s.check(["ip", "link", "add", DEVICE, "type", "wireguard"])
        s.check([
            "wg", "set", DEVICE, "listen-port", str(SERVER_PORT), "private-key", self.server_key_file,
            "peer", k.client_pub, "allowed-ips", f"{CLIENT_TUNNEL_ADDR}/32",
            "peer", k.probe_pub, "allowed-ips", f"{PROBE_TUNNEL_ADDR}/32",
        ])  # fmt: skip
        self._ip_batch(s, [f"addr add {SERVER_TUNNEL_ADDR}/{TUNNEL_PREFIXLEN} dev {DEVICE}", f"link set {DEVICE} up"])
        self.iperf_server = self._spawn(
            s, ["iperf3", "-s", "-B", SERVER_TUNNEL_ADDR, "-p", str(IPERF_PORT)], name="iperf3-server"
        )
        wait_until(
            lambda: s.check(["ss", "-Hltn", f"sport = :{IPERF_PORT}"]).strip(), timeout=5, desc="iperf3 -s listening"
        )

    def _shaping(self):
        for p in PATHS.values():
            for nsname, ifname in (p.upstream_if, p.downstream_if):
                self._tc(self.ns[nsname], ["qdisc", "add", "dev", ifname, "root", "handle", "1:", "netem", "limit", "10000"])
        self._tc(self.ns["relay2"], ["qdisc", "add", "dev", "r2-c", "clsact"])  # set_relay2_alias

    def _warm_neighbors(self):
        """
        Resolves every underlay neighbor (ARP/NDP) while the paths are still
        unshaped. Otherwise the first packet over each path waits for
        resolutions that cross the netem qdiscs once delays are set, and the
        daemon's first probe sample of every path is one extra RTT late (an
        outlier that skews the RTT spread for a whole window).
        """
        hops = [(self.client, p.addr) for p in PATHS.values()]
        for i in (1, 2, 3):
            near, far = (_v6(13, 1), _v6(13, 2)) if i == 3 else (_v4(10 + i, 1), _v4(10 + i, 2))
            hops += [(self.ns[f"relay{i}"], far), (self.server, near)]
        hops.append((self.server, _v4(0, 2)))
        ping = ["ping", "-n", "-q", "-c", "1", "-W", "2"]
        procs = [
            (ns, addr, ns.popen(ping + [addr], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)) for ns, addr in hops
        ]
        for ns, addr, p in procs:
            _, err = p.communicate()
            if p.returncode != 0:
                raise CommandError(f"[{ns.name}] ping {addr}: exit {p.returncode}: {err.decode().strip()}")

    def _spawn(self, ns, cmd, name=None, env=None, stdin=None):
        p = ManagedProcess(ns, cmd, name=name, env=env, stdin=stdin)
        self._procs.append(p)
        return p

    def spawn(self, nsname, cmd, name=None, env=None, stdin=None):
        """Starts a tracked ManagedProcess in namespace nsname; destroy() stops it."""
        return self._spawn(self.ns[nsname], cmd, name=name, env=env, stdin=stdin)

    def _tc(self, ns, args):
        ns.check(["tc", *args])

    # --- client wg0

    def _create_wg0(self, listen_port, endpoint):
        c, k = self.client, self.keys
        if self.userspace:
            self._wggo_bin = wireguard_go_binary()  # built once per process
            sock = f"/run/wireguard/{DEVICE}.sock"
            self._wggo = self._spawn(
                c, [self._wggo_bin, "-f", DEVICE], name="wireguard-go", env=dict(os.environ, LOG_LEVEL="error")
            )
            wait_until(
                lambda: c.run(["test", "-S", sock]).returncode == 0 or not self._wggo.running(),
                timeout=10,
                desc="wireguard-go UAPI socket",
            )
            if not self._wggo.running():
                raise RuntimeError(f"wireguard-go exited: {self._wggo.output()}")
        else:
            c.check(["ip", "link", "add", DEVICE, "type", "wireguard"])
        args = ["wg", "set", DEVICE, "private-key", self.client_key_file]
        if listen_port:
            args += ["listen-port", str(listen_port)]
        args += [
            "peer", k.server_pub, "endpoint", endpoint, "allowed-ips", "0.0.0.0/0",
            "persistent-keepalive", str(self.keepalive),
        ]  # fmt: skip
        c.check(args)
        self._ip_batch(c, [f"addr add {CLIENT_TUNNEL_ADDR}/{TUNNEL_PREFIXLEN} dev {DEVICE}", f"link set {DEVICE} up"])

    def _delete_wg0(self):
        if self.userspace:
            self._wggo.stop()
            self._procs.remove(self._wggo)
            self._wggo = None
            wait_until(
                lambda: self.client.run(["ip", "link", "show", DEVICE], capture_output=True).returncode != 0,
                timeout=5,
                desc="wireguard-go tun removal",
            )
        else:
            self.client.check(["ip", "link", "del", DEVICE])

    def recreate_wg0(self, listen_port=None, endpoint=None):
        """
        Deletes and recreates the client's wg0 with the same keys, address and
        keepalive, on a new random listen port (or listen_port), with the
        endpoint from the "config" (the initial path) unless given, like a
        netifd/wg-quick restart. Restores the fwmark setup if enabled.
        Returns the new port.
        """
        old = self.wg0().listen_port
        fwmark = self.fwmark_enabled
        if fwmark:
            self.disable_fwmark()
        self._delete_wg0()
        ep = endpoint or self.initial_endpoint
        for attempt in range(5):
            port = listen_port or random.choice([p for p in range(20000, 60000) if p != old])
            try:
                self._create_wg0(port, ep)
                break
            except CommandError:
                if listen_port or attempt == 4:
                    raise
                self._delete_wg0()
        if fwmark:
            self.enable_fwmark()
        return port

    def enable_fwmark(self, mark=FWMARK, table=FWMARK):
        """
        wg-quick style policy routing for wg0 (IPv4 only, as wg0's allowed IPs
        are 0.0.0.0/0): fwmark on wg0, `ip rule not fwmark M table T`, default
        dev wg0 in T, src_valid_mark=1, and wg-quick's `table ip wg-quick-wg0`
        that saves the mark of outgoing UDP in conntrack and restores it on
        replies (without it, rp_filter=1 drops the replies: their reverse
        route would be wg0). wg-quick's `suppress_prefixlength 0` rule is
        omitted on purpose: relays here sit on connected subnets, so it would
        let unmarked packets bypass wg0. Without it, unmarked packets to
        relay/server addresses route into wg0, as they do for real remote
        relays behind the default route.
        """
        c = self.client
        c.check(["wg", "set", DEVICE, "fwmark", str(mark)])
        self._sysctl(c, "net.ipv4.conf.all.src_valid_mark=1")
        self._ip_batch(c, [f"rule add not fwmark {mark} table {table}", f"route add default dev {DEVICE} table {table}"])
        c.check(
            ["nft", "-f", "-"],
            input=f"""table ip wg-quick-{DEVICE} {{
	chain premangle {{
		type filter hook prerouting priority mangle; policy accept;
		meta l4proto udp meta mark set ct mark
	}}
	chain postmangle {{
		type filter hook postrouting priority mangle; policy accept;
		meta l4proto udp meta mark {mark} ct mark set meta mark
	}}
}}
""",
        )
        self.fwmark_enabled = (mark, table)

    def disable_fwmark(self):
        if not self.fwmark_enabled:
            return
        mark, table = self.fwmark_enabled
        c = self.client
        c.run(["ip", "route", "del", "default", "table", str(table)], capture_output=True)
        c.check(["ip", "rule", "del", "not", "fwmark", str(mark), "table", str(table)])
        c.check(["nft", "delete", "table", "ip", f"wg-quick-{DEVICE}"])
        if c.run(["ip", "link", "show", DEVICE], capture_output=True).returncode == 0:
            c.check(["wg", "set", DEVICE, "fwmark", "0"])
        self.fwmark_enabled = False

    def wg0(self):
        """Parsed `wg show wg0 dump` of the client."""
        return parse_wg_dump(self.client.check(["wg", "show", DEVICE, "dump"]))

    def wg0_peer(self):
        return self.wg0().peers[self.keys.server_pub]

    def wg0_endpoint(self):
        return self.wg0_peer().endpoint

    def wg0_handshake(self):
        return self.wg0_peer().latest_handshake

    def wg0_transfer(self):
        """(rx, tx) bytes of the managed peer."""
        p = self.wg0_peer()
        return p.rx, p.tx

    def wg_set_endpoint(self, endpoint):
        """Plain `wg set wg0 peer <server> endpoint E` (an external change)."""
        if isinstance(endpoint, PathSpec):
            endpoint = endpoint.endpoint
        self.client.check(["wg", "set", DEVICE, "peer", self.keys.server_pub, "endpoint", endpoint])

    def wg_set_keepalive(self, seconds):
        self.client.check(["wg", "set", DEVICE, "peer", self.keys.server_pub, "persistent-keepalive", str(seconds)])

    def wait_wg0_endpoint(self, endpoint, timeout=5.0):
        if isinstance(endpoint, PathSpec):
            endpoint = endpoint.endpoint
        return wait_until(lambda: self.wg0_endpoint() == endpoint, timeout, desc=f"wg0 endpoint {endpoint}")

    def server_wg(self):
        return parse_wg_dump(self.server.check(["wg", "show", DEVICE, "dump"]))

    def server_peer_endpoint(self, which="client"):
        """Endpoint the server currently has for the client's wg0 ("client") or the probe ("probe")."""
        key = self.keys.client_pub if which == "client" else self.keys.probe_pub
        return self.server_wg().peers[key].endpoint

    # --- paths

    def set_path(
        self,
        name,
        delay_ms=0,
        jitter_ms=0,
        distribution="normal",
        loss_pct=0,
        blackhole=False,
        spike_ms=0,
        spike_pct=0,
        direction="both",
        limit=10000,
    ):
        """
        Reconfigures the netem qdisc(s) of a path with `tc qdisc change`.
        Parameters apply per direction ("both", "up" = client->server,
        "down" = server->client); a round trip over "both" therefore adds
        2*delay_ms and loses 1-(1-loss)^2. Unspecified parameters reset to off.

        jitter_ms: netem jitter with an explicit distribution table
          ("normal", "uniform", "pareto", "paretonormal", "experimental").
        spike_ms/spike_pct: "spike_pct % of packets get +spike_ms" on top of
          delay_ms (a generated two-point netem distribution table); excludes
          jitter_ms. Jittered netem reorders packets.
        blackhole: 100% loss.
        """
        p = PATHS[name]
        args = ["limit", str(limit)]
        base = f"{delay_ms}ms" if delay_ms else "1us"  # tc refuses a distribution without a latency
        if spike_ms and spike_pct:
            if jitter_ms:
                raise ValueError("spike and jitter are exclusive")
            args += ["delay", base, f"{spike_ms}ms", "distribution", _spike_dist(self.tc_lib_dir, spike_pct)]
        elif jitter_ms:
            args += ["delay", base, f"{jitter_ms}ms", "distribution", distribution]
        elif delay_ms:
            args += ["delay", f"{delay_ms}ms"]
        loss = 100 if blackhole else loss_pct
        if loss:
            args += ["loss", f"{loss}%"]
        targets = {"both": (p.upstream_if, p.downstream_if), "up": (p.upstream_if,), "down": (p.downstream_if,)}
        for nsname, ifname in targets[direction]:
            self._tc(self.ns[nsname], ["qdisc", "change", "dev", ifname, "root", "handle", "1:", "netem", *args])

    def reset_paths(self):
        for name in PATHS:
            self.set_path(name)

    def path_qdisc(self, name, direction="up"):
        """`tc qdisc show` line(s) for one direction of a path."""
        p = PATHS[name]
        nsname, ifname = p.upstream_if if direction == "up" else p.downstream_if
        return self.ns[nsname].check(["tc", "qdisc", "show", "dev", ifname]).strip()

    def set_relay2_alias(self, on):
        """
        relay2 replies from its alias IP when on: a stateless source rewrite
        on relay2's client-side egress, after NAT (tc clsact egress, flower +
        pedit + csum; nft payload mangling is EPERM in a user namespace on
        this kernel). DNAT accepts both addresses, so the client roaming to
        the alias keeps working.
        """
        r = self.ns["relay2"]
        p = PATHS["relay2"]
        r.run(["tc", "filter", "del", "dev", "r2-c", "egress"], capture_output=True)  # fails harmlessly when empty
        if on:
            r.check([
                "tc", "filter", "add", "dev", "r2-c", "egress", "protocol", "ip", "flower",
                "ip_proto", "udp", "src_ip", p.addr, "src_port", str(p.port),
                "action", "pedit", "ex", "munge", "ip", "src", "set", p.alias, "pipe",
                "action", "csum", "ip4h", "udp",
            ])  # fmt: skip

    def flows(self, name):
        """Per-path UDP counters keyed by the client's port (see Flows)."""
        p = PATHS[name]
        ns = self.ns[p.relay] if p.relay else self.server
        res = []
        for s in ("flows_up", "flows_down"):
            out = json.loads(ns.check(["nft", "-j", "list", "set", "inet", "harness", s]))
            st = next(o["set"] for o in out["nftables"] if "set" in o)
            d = {}
            for e in st.get("elem", []):
                el = e["elem"]
                d[el["val"]] = (el["counter"]["packets"], el["counter"]["bytes"])
            res.append(d)
        return Flows(*res)

    def reset_flows(self, name=None):
        for n in [name] if name else PATHS:
            p = PATHS[n]
            ns = self.ns[p.relay] if p.relay else self.server
            for s in ("flows_up", "flows_down"):
                ns.check(["nft", "flush", "set", "inet", "harness", s])

    # --- traffic

    def ping(self, count=5, interval=0.2, timeout=1.0, size=56, target=SERVER_TUNNEL_ADDR):
        """ping via wg0 from CLIENT_TUNNEL_ADDR; never raises on loss."""
        cmd = [
            "ping", "-n", "-c", str(count), "-i", str(interval), "-W", str(timeout), "-s", str(size),
            "-I", CLIENT_TUNNEL_ADDR, target,
        ]  # fmt: skip
        p = self.client.run(cmd, capture_output=True, text=True, timeout=count * interval + timeout + 10)
        rtts = {int(m.group(1)): float(m.group(2)) for m in re.finditer(r"icmp_seq=(\d+) .*time=([\d.]+) ms", p.stdout)}
        return PingResult(count, rtts, p.stdout + p.stderr)

    def iperf3(self, duration=10, reverse=False, bidir=False, interval=0.5, extra=()):
        """Starts `iperf3 -c` (TCP, via wg0) in the client namespace; returns an Iperf3Run."""
        cmd = [
            "iperf3", "-c", SERVER_TUNNEL_ADDR, "-B", CLIENT_TUNNEL_ADDR, "-p", str(IPERF_PORT),
            "-t", str(duration), "-i", str(interval), "-J",
        ]  # fmt: skip
        if reverse:
            cmd.append("-R")
        if bidir:
            cmd.append("--bidir")
        cmd += list(extra)
        return Iperf3Run(self._spawn(self.client, cmd, name="iperf3-client"))

    # --- daemon

    def daemon_args(self, flags=None, binary=None):
        flags = {**SCALED_FLAGS, **(flags or {})}
        args = [
            *DAEMON_PRIVILEGES,
            str(binary or DAEMON_BIN),
            f"--device={DEVICE}",
            f"--probe-config={self.probe_config}",
            f"--endpoints={self.endpoints_file}",
            f"--probe-addr={PROBE_TUNNEL_ADDR}",
            f"--target={SERVER_TUNNEL_ADDR}",
        ]
        for k, v in flags.items():
            if v is None:
                continue
            args.append(f"--{k}" if v is True else f"--{k}={'false' if v is False else v}")
        return args

    def start_daemon(self, flags=None, extra_args=(), binary=None, env=None, name="daemon"):
        """
        Starts the daemon in the client namespace (with its private /run) and
        returns its ManagedProcess (combined stdout/stderr lines,
        wait_for_log, signal, stop). flags override SCALED_FLAGS (None drops
        a flag, True -> --flag, False -> --flag=false). destroy() stops it.
        """
        args = self.daemon_args(flags, binary)
        if not os.path.exists(binary or DAEMON_BIN):
            raise FileNotFoundError(f"{binary or DAEMON_BIN} not found; run `make build` (or set WGSTEER_BIN)")
        return self._spawn(self.client, args + list(extra_args), name=name, env=env)

    def nft_table(self, name=NFT_TABLE, family="inet"):
        """The daemon's table in the client namespace (None if absent)."""
        return nft_table(self.client, name, family)

    def nft_tables(self):
        return nft_tables(self.client)
