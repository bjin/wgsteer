"""Proves the namespace harness without the daemon.

Run: python3 tests/integration/test_topology.py -v
"""

import os
import signal
import statistics
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from framework import setup_userns  # noqa: E402
from topology import (  # noqa: E402
    DEVICE,
    FWMARK,
    NFT_TABLE,
    PATH_NAMES,
    PATHS,
    PROBE_TUNNEL_ADDR,
    SERVER_TUNNEL_ADDR,
    TUNNEL_PREFIX,
    TUNNEL_PREFIXLEN,
    Topology,
    wait_until,
)


class TopologyTestBase(unittest.TestCase):
    topo_kwargs = {}

    def setUp(self):
        self.topo = Topology(**self.topo_kwargs).build()
        self.addCleanup(self.topo.destroy)

    def use_path(self, name, pings=3):
        """Points wg0 at a path and pings until the server has roamed to it."""
        t = self.topo
        t.wg_set_endpoint(PATHS[name])
        r = t.ping(count=pings, interval=0.05)
        self.assertEqual(t.wg0_endpoint(), PATHS[name].endpoint)
        return r


class KernelTopologyTest(TopologyTestBase):
    def test_files(self):
        t = self.topo
        with open(t.endpoints_file) as f:
            self.assertEqual(f.read().split(), [PATHS[n].endpoint for n in PATH_NAMES])
        self.assertEqual(PATH_NAMES[-1], "direct")
        self.assertTrue(PATHS["relay3"].endpoint.startswith("["))
        with open(t.probe_config) as f:
            conf = dict(l.split("=", 1) for l in f.read().split())
        self.assertEqual(set(conf), {"private_key", "public_key", "allowed_ip"})
        self.assertEqual(len(conf["private_key"]), 64)
        self.assertEqual(bytes.fromhex(conf["public_key"]).hex(), conf["public_key"])
        self.assertEqual(conf["allowed_ip"], f"{SERVER_TUNNEL_ADDR}/32")
        # The probe identity is registered on the server, but no interface carries its address.
        self.assertEqual(t.server_wg().peers[t.keys.probe_pub].allowed_ips, [f"{PROBE_TUNNEL_ADDR}/32"])
        self.assertNotIn(PROBE_TUNNEL_ADDR, t.client.check(["ip", "-o", "addr"]))
        # Only the tunnel subnet is routed into wg0.
        self.assertEqual(
            t.client.check(["ip", "-o", "route", "show", "dev", DEVICE]).split()[0], f"{TUNNEL_PREFIX}.0/{TUNNEL_PREFIXLEN}"
        )
        peer = t.wg0_peer()
        self.assertEqual(peer.allowed_ips, ["0.0.0.0/0"])
        self.assertEqual(peer.keepalive, 25)
        self.assertEqual(peer.endpoint, PATHS["relay1"].endpoint)

    def test_ping_each_path(self):
        t = self.topo
        port = t.wg0().listen_port
        for name in PATH_NAMES:
            with self.subTest(path=name):
                t.reset_flows()
                self.use_path(name)
                r = t.ping(count=5, interval=0.05)
                self.assertEqual(r.received, 5, r.output)
                self.assertEqual(t.wg0_endpoint(), PATHS[name].endpoint)
                # The server sees the path's own source (relay masquerade or the client's direct address).
                srv_addr = t.server_peer_endpoint().rsplit(":", 1)[0].strip("[]")
                self.assertEqual(srv_addr, PATHS[name].server_sees)
                # Per-path counters attribute wg0's flow by its listen port, on this path only.
                fl = t.flows(name)
                self.assertGreaterEqual(fl.up.get(port, (0, 0))[0], 5, fl)
                self.assertGreaterEqual(fl.down.get(port, (0, 0))[0], 5, fl)
                for other in PATH_NAMES:
                    if other != name:
                        self.assertNotIn(port, t.flows(other).up, other)

    def test_netem_delay_one_path_only(self):
        t = self.topo
        t.set_path("relay2", delay_ms=25)
        self.assertIn("delay 25ms", t.path_qdisc("relay2", "up"))
        self.use_path("relay2")
        slow = t.ping(count=5, interval=0.05).rtt_list
        self.use_path("relay1")
        fast = t.ping(count=5, interval=0.05).rtt_list
        self.assertEqual(len(slow), 5)
        self.assertEqual(len(fast), 5)
        self.assertGreaterEqual(min(slow), 50.0, slow)
        self.assertLess(max(fast), 20.0, fast)
        # Runtime change on the same qdisc, one direction only.
        t.set_path("relay2", delay_ms=10, direction="down")
        t.set_path("relay2", direction="up")
        self.use_path("relay2")
        rtts = t.ping(count=5, interval=0.05).rtt_list
        self.assertTrue(all(10.0 <= x < 20.0 for x in rtts), rtts)

    def test_jitter_and_spike(self):
        t = self.topo
        t.set_path("relay1", delay_ms=10, jitter_ms=5, distribution="normal")
        self.assertRegex(t.path_qdisc("relay1"), r"delay 10ms\s+5ms")
        r = t.ping(count=40, interval=0.02)
        self.assertGreaterEqual(r.received, 38)
        self.assertGreater(statistics.pstdev(r.rtt_list), 1.0, r.rtt_list)
        # 30% of packets +100 ms, shaped upstream only: ~30% of round trips are spikes.
        t.set_path("relay1", delay_ms=5, spike_ms=100, spike_pct=30, direction="up")
        t.set_path("relay1", direction="down")
        r = t.ping(count=150, interval=0.02, timeout=2)
        self.assertGreaterEqual(r.received, 148, r.output)
        spikes = [x for x in r.rtt_list if x >= 100]
        normal = [x for x in r.rtt_list if x < 100]
        self.assertTrue(all(x < 20 for x in normal), normal)
        self.assertTrue(all(100 <= x < 130 for x in spikes), spikes)
        frac = len(spikes) / r.received
        self.assertTrue(0.15 <= frac <= 0.45, frac)

    def test_blackhole_and_loss(self):
        t = self.topo
        t.set_path("relay1", blackhole=True)
        self.assertEqual(t.ping(count=5, interval=0.05, timeout=0.5).received, 0)
        self.use_path("relay2")  # other paths unaffected
        self.assertEqual(t.ping(count=5, interval=0.05).received, 5)
        t.set_path("relay1")
        self.use_path("relay1")
        self.assertEqual(t.ping(count=5, interval=0.05).received, 5)
        t.set_path("relay1", loss_pct=50, direction="up")
        r = t.ping(count=100, interval=0.01, timeout=0.5)
        self.assertTrue(0.3 <= r.loss <= 0.7, r.loss)

    def test_relay2_alias_rewrite(self):
        t = self.topo
        p = PATHS["relay2"]
        self.use_path("relay2")
        t.set_relay2_alias(True)
        self.assertEqual(t.ping(count=3, interval=0.05).received, 3)
        self.assertEqual(t.wg0_endpoint(), p.alias_endpoint)
        # Traffic keeps flowing on the alias (DNAT accepts it) and the client stays there.
        self.assertEqual(t.ping(count=5, interval=0.05).received, 5)
        self.assertEqual(t.wg0_endpoint(), p.alias_endpoint)
        t.set_relay2_alias(False)
        t.wg_set_endpoint(p)
        self.assertEqual(t.ping(count=3, interval=0.05).received, 3)
        self.assertEqual(t.wg0_endpoint(), p.endpoint)

    def test_ipv6_path(self):
        t = self.topo
        self.use_path("relay3")
        self.assertEqual(t.wg0_endpoint(), PATHS["relay3"].endpoint)
        self.assertRegex(PATHS["relay3"].endpoint, r"^\[[0-9a-f:]+\]:\d+$")
        self.assertEqual(t.ping(count=5, interval=0.05).received, 5)
        self.assertEqual(t.server_peer_endpoint().rsplit(":", 1)[0], f"[{PATHS['relay3'].server_sees}]")

    def test_fwmark_variant(self):
        t = self.topo
        relay = PATHS["relay1"].addr
        t.enable_fwmark()
        self.assertEqual(t.wg0().fwmark, FWMARK)
        # Unmarked traffic to a relay is routed into wg0; marked traffic goes direct.
        self.assertIn(f"dev {DEVICE}", t.client.check(["ip", "route", "get", relay]))
        self.assertIn("dev c-r1", t.client.check(["ip", "route", "get", relay, "mark", str(FWMARK)]))
        self.assertEqual(t.ping(count=5, interval=0.05).received, 5)
        # The fwmark setup survives a device recreation.
        t.recreate_wg0()
        self.assertEqual(t.wg0().fwmark, FWMARK)
        wait_until(lambda: t.ping(count=1, timeout=1).received, timeout=10, interval=0, desc="ping after recreate")
        t.disable_fwmark()
        self.assertIn("dev c-r1", t.client.check(["ip", "route", "get", relay]))

    def test_recreate_wg0(self):
        t = self.topo
        before = t.wg0()
        self.use_path("relay2")
        port = t.recreate_wg0()
        after = t.wg0()
        self.assertNotEqual(port, before.listen_port)
        self.assertEqual(after.listen_port, port)
        self.assertEqual(after.public_key, before.public_key)
        self.assertEqual(t.wg0_endpoint(), PATHS["relay1"].endpoint)  # the "configured" endpoint
        wait_until(lambda: t.ping(count=1, timeout=1).received, timeout=10, interval=0, desc="ping after recreate")

    def test_nft_inspection_owner_table(self):
        """Parses an owner-flag table shaped like the daemon's, held open by `nft -i`."""
        t = self.topo
        port = t.wg0().listen_port
        denied = [PATHS["relay2"], PATHS["relay3"]]
        rules = []
        for p in denied:
            fam = "ip6" if p.family == "ipv6" else "ip"
            rules.append(f"add rule inet {NFT_TABLE} input udp dport {port} {fam} saddr {p.addr} udp sport {p.port} counter drop\n")
        holder = t.spawn("client", ["nft", "-i"], name="nft-i", stdin=True)
        holder.write_stdin(
            f"add table inet {NFT_TABLE} {{ flags owner; }}\n"
            f"add chain inet {NFT_TABLE} input {{ type filter hook input priority filter - 5; policy accept; }}\n"
            + "".join(rules)
        )
        wait_until(lambda: (tab := t.nft_table()) is not None and len(tab.rules) == 2, timeout=5, desc="owner table")
        tables = {(x["family"], x["name"]): x for x in t.nft_tables()}
        self.assertIn("owner", tables[("inet", NFT_TABLE)]["flags"])
        tab = t.nft_table()
        self.assertTrue(tab.owned)
        self.assertEqual(tab.progname, "nft")
        self.assertEqual(tab.chains["input"], {"type": "filter", "hook": "input", "prio": -5, "policy": "accept"})
        self.assertEqual(tab.dports(), {port})
        self.assertEqual(tab.denied_endpoints(), {p.endpoint for p in denied})
        self.assertEqual({r.family for r in tab.rules}, {"ip", "ip6"})
        # Packets from a denied source are counted and dropped (no roaming to them).
        self.use_path("relay1")
        t.wg_set_endpoint(PATHS["relay2"])
        t.ping(count=3, interval=0.05, timeout=0.3)
        self.assertGreater(t.nft_table().counters()[PATHS["relay2"].endpoint][0], 0)
        self.assertEqual(t.wg0_endpoint(), PATHS["relay2"].endpoint)
        # Owner gone -> table gone, without anybody deleting it.
        holder.kill()
        wait_until(lambda: t.nft_table() is None, timeout=5, desc="owned table removal")

    def test_managed_process(self):
        t = self.topo
        script = (
            'trap \'echo got-usr1 >&2\' USR1; trap \'echo bye; exit 3\' TERM; '
            'echo "start pid=$$" >&2; while :; do sleep 0.05; done'
        )
        p = t.spawn("client", ["sh", "-c", script], name="stub")
        m = p.wait_for_log(r"start pid=(\d+)", timeout=5)
        self.assertEqual(int(m.group(1)), p.pid)
        mark = p.mark()
        p.signal(signal.SIGUSR1)
        p.wait_for_log("got-usr1", timeout=5, since=mark)
        with self.assertRaises(TimeoutError):
            p.wait_for_log("never", timeout=0.2)
        self.assertEqual(p.stop(), 3)
        self.assertEqual(p.lines()[-1], "bye")
        with self.assertRaises(TimeoutError):
            p.wait_for_log("never", timeout=5)  # exited: fails fast

    def test_negative_control_roaming_reverts(self):
        """Negative control: under load, a plain `wg set` to another relay is undone by roaming."""
        t = self.topo
        t.set_path("relay1", delay_ms=10)
        t.set_path("relay2", delay_ms=10)
        self.use_path("relay1")
        run = t.iperf3(duration=6, bidir=True)
        rx0 = t.wg0_transfer()[0]
        wait_until(lambda: t.wg0_transfer()[0] > rx0 + 4_000_000, timeout=5, desc="iperf3 load")
        hs = t.wg0_handshake()
        t.wg_set_endpoint(PATHS["relay2"])
        seen = []
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            seen.append(t.wg0_endpoint())
            time.sleep(0.02)
        run.wait(timeout=30)
        self.assertIn(PATHS["relay1"].endpoint, seen, "wg0 never roamed back")
        self.assertEqual(seen[-1], PATHS["relay1"].endpoint, seen[-20:])
        self.assertEqual(t.wg0_handshake(), hs)  # roaming, not a new session


class UserspaceTopologyTest(TopologyTestBase):
    topo_kwargs = {"userspace": True}

    def test_ping_and_uapi(self):
        t = self.topo
        # The UAPI socket exists only in the client's private /run.
        self.assertEqual(t.client.run(["test", "-S", f"/run/wireguard/{DEVICE}.sock"]).returncode, 0)
        self.assertFalse(os.path.exists(f"/run/wireguard/{DEVICE}.sock"))
        self.assertIn("tun", t.client.check(["ip", "-d", "link", "show", DEVICE]))
        dev = t.wg0()
        self.assertGreater(dev.listen_port, 0)
        for name in ("relay1", "relay3", "direct"):
            with self.subTest(path=name):
                self.use_path(name)
                self.assertEqual(t.ping(count=5, interval=0.05).received, 5)
        port = t.recreate_wg0()
        self.assertEqual(t.wg0().listen_port, port)
        wait_until(lambda: t.ping(count=1, timeout=1).received, timeout=10, interval=0, desc="ping after recreate")


if __name__ == "__main__":
    setup_userns()
    unittest.main()
