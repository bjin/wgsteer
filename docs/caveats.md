# Caveats

Known limits of the design and the implementation. Numbers assume the defaults (1 s probe interval, 5 endpoints) unless stated.

## Probing and measurement

1. **The probe measures a proxy.** Its outer 5-tuple differs from the live device's, so ECMP or per-flow relay state (e.g. phantun sessions) can put it on a different sub-path. A relay broken only for the device's flow goes undetected.
2. **Self-load bias.** The active relay carries the device's traffic, so under heavy load its probes see the congestion the device causes while idle candidates look better. That can cause ping-pong when the bottleneck is the relay rather than the shared uplink. Noise gate, margin, accumulators, restore backoff and cooldown dampen it; nothing eliminates it.
3. **Statistical power.** One probe per interval is shared by all endpoints, so each gets one sample per N intervals. With n_eff ≈ 158 the loss standard error is about ±1.7 pp at 5% and ±2.4 pp at 10% loss. Loss differences of a few points are treated as noise; 3% vs 10% sits at the edge of the gate (calibration cases S4, S4′); only clear jumps drive loss-based switches. Measured in simulation ([scoring.md](scoring.md#behavioral-targets-testtargets), 5 endpoints at 1 s): a +60 ms step switches in 50–60 s, a jump to 30% loss in a median of 3.5 min, an outage in about K × N × interval (K = 4 at 5% base loss, 5 at 10%: median 16 s). The main lever is a shorter `--probe-interval`: detection scales roughly linearly, and probe traffic grows in proportion.
4. **Loss 5% → 50% is not always caught within 4 minutes.** The long half-life the defaults need for a 20% vs 3% loss difference makes loss tracking slower; one simulated seed in twelve took 4.75 minutes. See [scoring.md](scoring.md#the-unmet-50-loss-tail).
5. **Bursty loss** breaks the binomial assumption behind the loss SE: real loss is overdispersed, so the gate lets more through, and episodes shorter than the detection time (1–2 min) cause churn switches (simulation: 2.7 degradation switches / 12 h with 60 s episodes every 10 min). Tune against real `--dry-run` data (`tools/tune.py`).
6. **Near-margin pairs.** When two endpoints truly differ by about the margin, noise alternately proves and disproves it. The 45 min wait-to-restore and the restore backoff bound the ping-pong (1.09 switches / h in the worst simulated case); they do not eliminate it. Restores can also step through intermediate endpoints on equal paths.
7. **Late replies count as loss.** A path whose RTT approaches `--probe-timeout` looks lossy, by design.
8. **Small probes do not detect path-MTU black holes.** Paths differ in outer overhead (IPv6 adds 20 bytes; each relay transport adds its own); the device's MTU must fit the smallest. To probe with full-size packets, set `--probe-mtu` to the live device's MTU and `--probe-size` to its maximum, `--probe-mtu` minus 28 (IPv4 tunnel addresses) or 48 (IPv6), at traffic cost. The probe device MTU (default 1420, WireGuard's default) is a command-line setting because the UAPI probe config has no MTU key; wireguard-go pads each packet to a multiple of 16 bytes, capped at that MTU, so the outer packet matches what the live device would send for the same inner size (measured: a 1352-byte payload gives 1440-byte outer IPv4 packets at `--probe-mtu 1380`, 1452 at 1420). `--probe-mtu` ranges from 576 (IPv4 tunnel addresses) or 1280 (IPv6) to 65475: with the 32-byte WireGuard header and tag, a full-size probe is then exactly the 65507-byte UDP payload limit of IPv4.
9. **Probe traffic.** At the default 56-byte payload each echo and reply is about 156 bytes on the wire with IPv4 outer headers (84-byte inner packet padded to 96, +32 WireGuard, +28 UDP/IPv4), about 27 MB/day across all endpoints at 1 probe/s.
10. **The probe session can expire** when every path is bad. Its slots are then invalid and nothing switches. If the server or the local uplink is down, everything is down and nothing switches; losses during such a common-mode outage do not count toward the outage rule afterwards.
11. **Server side.** The server must have the probe peer, answer ICMP from the probe address and keep roaming enabled. It sees the probe roam every interval, which is harmless. The probe identity must never reuse the device's key, or the server flaps the live peer (startup refuses an equal key).
12. **Outer routing.** The probe's outer packets must route like the device's. The fwmark is copied; other policy routing that singles out the device's socket needs equivalent treatment. Never route a candidate address into the device (routing loop).

## Roaming and switching

13. **The roaming-disable API is an upstream quirk** for mobile clients (`DisableSomeRoamingForBrokenMobileSemantics`). It only takes effect if the peer is created with an endpoint after the call. `TestIntegrationLateReplyDoesNotRoam` guards it against wireguard-go upgrades.
14. **Every switch drops about 1–2 RTT of downstream traffic.** Late packets via the old path are dropped, and the server keeps sending there until a packet via the new path arrives. Under heavy load that is a burst loss (TCP recovers), which is why switches are rate-limited. There is no re-handshake; the session survives. Packets reordered past the replay window right after a switch are dropped as replays.
15. **Server-side transient flap.** Upstream packets sent via the old path before the switch may arrive after the first new-path packet, and the server roams back briefly. It settles on its own because the device never sends via the old path again.
16. **The block→set gap** is the 1 ms drain wait plus one netlink round trip (about 1.1 ms); old-path packets arriving in it are dropped by design. Packets that passed the input hook *before* the commit can still be queued inside kernel WireGuard (decryption runs asynchronously); the 1 ms wait lets them be processed before the endpoint changes. If one is processed later anyway (heavy load), it roams the device back to the old, denied endpoint; the post-switch check 200 ms after the switch re-asserts the target, so the window is about 200 ms instead of a whole `--reconcile-interval`.
17. **The kick briefly changes the peer's persistent keepalive.** A netlink call failing part-way is repaired: reconcile redoes the write with the original keepalive ([switching.md](switching.md#reconcile)). A crash between the calls still leaves 0 or 1 s until the device is reconfigured. The kick needs the interface to be up.
18. **Listen-port changes:** after the device is recreated, the old rules match nothing for up to one reconcile interval; roaming is unrestricted then (harmless).
19. **netifd/wg-quick reset to a denied candidate:** the tunnel is dead for up to one reconcile interval until the re-assert.
20. **Crash safety relies on the owner flag (Linux >= 5.12).** On any exit the table vanishes and the device roams freely until the service manager restarts the daemon (safe, just unmanaged). A hang is covered only by the watchdog: a loop stalled for less than `--watchdog` while netifd resets the device to a denied endpoint leaves the tunnel dead for that long. A restart policy is still mandatory to resume steering.
21. **A clean stop deletes the table:** roaming is unrestricted while the daemon is down and the device keeps its last endpoint. This is the way to inhibit or pin.
22. **Operators cannot delete or edit the owned table** while the daemon runs (`Operation not permitted`); stop the service instead. `nft flush ruleset` from other tools skips it, which is intended.
23. **A failed nft transaction leaves the previous rules in force** and keeps the owner socket. Recovery never opens a second connection; replacing the connection starts with `CloseLasting()`, which briefly leaves the device unprotected (plain roaming) until the rebuild.
24. **Manual `wg set`** to a listed endpoint is reverted by design. To pin, stop the service.
25. **Aliases are learned only by observation.** An alias of a non-selected candidate that was never seen as the device's endpoint is not denied. Fix it by listing the address or by fixing the relay's reply source. Unlisted sources are never blocked otherwise; that is the trade-off for NAT tolerance. The same holds for the device's unlisted endpoint at startup: the startup switch leaves it allowed, so late packets from it can still roam the device there (it is then learned as the new selection's alias and not fought).
26. **wgctrl returns endpoints as `net.UDPAddr`**, sometimes with 16-byte IPv4. All comparisons use normalized (unmapped) `netip.AddrPort` values.
27. **Netlink reads need `CAP_NET_ADMIN`**, so `--dry-run` needs it too. It is the only capability needed; see [design.md](design.md#privileges) for running as a non-root user, the userspace-device socket constraint, and why OpenWrt procd needs ujail (or a file capability) to pass it on.
28. **One daemon per device.** The table name embeds the device name; a second instance refuses to start. `nft` CLI users may need to quote table names containing `-`.
29. **Suspend/resume** and other gaps above 10 × `--probe-interval` reset accumulators and loss runs so stale state cannot trigger a switch. The loop clock (`CLOCK_BOOTTIME`) sees the suspend; the watchdog (monotonic) does not.
30. **A pending switch is deferred while the device is detached** and runs on the first tick after it reappears.

## Upstream wireguard-go bind bug

The pinned `golang.zx2c4.com/wireguard v0.0.0-20261006164505-2631ce99a06f` has a bug in `conn/bind_std.go`, `StdNetBind.Send`, lines 366–376:

- send addresses come from a `sync.Pool` of `*net.UDPAddr`;
- an IPv4 send reslices the pooled `ua.IP` to 4 bytes;
- a later IPv6 send does `copy(ua.IP, as16[:])`, which copies only 4 bytes into the shortened slice before reslicing it to 16, so bytes 4–15 are left over from an earlier IPv6 destination.

Observed effect: `sendmmsg` to `fd00:231::` instead of `fd00:231:3::1` (`ENETUNREACH`). The probe alternates endpoints and families every slot, so its IPv6 endpoints would look mostly lossy; a userspace live device loses the first packets after a v4→v6 endpoint change.

Workaround: the probe uses its own bind (`udpBind`, `internal/probe/bind.go`): one IPv4 and one IPv6 socket on a shared port, one packet per receive, a fresh destination per send, `SO_MARK` on both sockets. Drop it once upstream is fixed; the check is the send pattern of `TestUDPBindAlternatingFamilies` run against `conn.NewStdNetBind()` (the pinned version loses nearly every IPv6 packet there).

**Upstream fix.** [wireguard-go PR #135](https://github.com/WireGuard/wireguard-go/pull/135) (open since 2025-12-20, not merged as of 2026-10-21) moves each resize before the copy. That is correct: pooled addresses are always allocated with 16 bytes and `Send` is the only code that reslices them, so `ua.IP[:16]` is always in capacity and the copy then overwrites every byte. Verified with the send pattern above: the pinned bind delivered 0/50 IPv6 datagrams to `::1`, the same version with the PR applied 50/50; wireguard-go's own `conn` tests pass with it under `-race`.

Who is affected:

| Component | Affected | Fixed by |
|---|---|---|
| The probe | No (own `udpBind`) | — |
| A kernel live device | No | — |
| A wireguard-go live device | Yes: after an IPv4→IPv6 endpoint switch, one IPv6 send per pooled address last used for IPv4 (the kick included) is lost or goes to another IPv6 peer that shares the first 32 bits; the pool is per scheduler P, so such losses can come seconds after the switch | Its own wireguard-go build carrying the fix; wgsteer's `go.mod` cannot change a separately built binary |
| The namespace harness's userspace wg0 | No: built with the PR applied ([testing.md](testing.md#host-quirks)) | `_WGGO_BIND_FIX` in `tests/integration/topology.py` |

Carrying the patch in wgsteer would be easy (a `replace` directive in `go.mod`, which applies because wgsteer is the main module) but is deliberately not done: it would only allow deleting `udpBind`. The PR author's fork (`github.com/mp2720/wireguard-go v0.0.0-20251220215513-b45f43da38b4`) works as a replacement but has diverged from the pinned upstream commit (1 ahead, 2 behind: it lacks a handshake-response race fix and a TUN GRO header fix), so it would silently roll those back. A correct carried patch needs an own fork at the pinned upstream commit with the PR commit cherry-picked (or a local-path `replace` to a patched copy in the repo), rebased on every upgrade. When the PR is merged: bump the pin, run the `TestUDPBindAlternatingFamilies` send pattern against `conn.NewStdNetBind()`, then drop `udpBind` and the harness's `_WGGO_BIND_FIX` (its build fails once the patch no longer applies).

## No 32-bit builds

wgsteer builds only for 64-bit targets. The pinned `github.com/google/nftables v0.3.1-0.20260430172505-f9b52ed2ba65` (upstream master as of 2026-10-25) does not compile where `int` is 32 bits:

```
conn.go:538:93: cannot use math.MaxUint32 (untyped int constant 4294967295) as int value in argument to fmt.Sprintf (overflows)
```

`allocateTransactionID` passes the untyped constant `math.MaxUint32` to `fmt.Sprintf`, which converts it to `int`. No upstream issue or fix was found (2026-10-25). The pin cannot move back: v0.3.0 has no owner-flag tables.

With that argument changed to `uint32(math.MaxUint32)` (a patched copy of the module through a temporary `go.work` `replace`), `go build ./cmd/wgsteer` and `go vet ./...` pass for `arm` (`GOARM=5` and `7`), `mips` and `mipsle` (`GOMIPS=softfloat`); nothing has been run on 32-bit hardware. Shipping that would need a carried patch like the one discussed above, which is not done. When upstream is fixed: bump the pin, run the tests on a 32-bit host (or under qemu-user), and add the targets to the release matrix in `.github/workflows/ci.yml`.

Release binaries therefore cover `linux/amd64`, `linux/arm64` and `linux/mips64` (`GOMIPS64=softfloat`). Among OpenWrt targets that includes `x86/64`, `mediatek/filogic`, `qualcommax`, `rockchip`, `bcm27xx` (bcm2710 and later) and `octeon`, but not the 32-bit `ramips` (mt7621, mt76x8), `ath79`, `ipq40xx` or `mvebu`.
