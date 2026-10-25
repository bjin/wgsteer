# Agent guidelines for wgsteer

Go daemon that keeps one WireGuard client peer on the best of several equivalent endpoints: it probes every candidate through a separate WireGuard identity, scores them, and switches the live peer endpoint behind an nftables deny-list. Overview: [README.md](README.md). Details: [docs/](docs/).

## Build and test

| Command | What it does |
|---|---|
| `make build` | Static binary `./wgsteer` (`CGO_ENABLED=0`, `-trimpath`, `-s -w`) |
| `make build-arm64` | `./wgsteer-arm64` |
| `make test` | `gofmt -l` must be empty, `go vet ./...`, `go test ./...` (no privileges; privileged tests skip) |
| `make integration` | Builds, downloads the modules, runs the `internal/nftable` and `internal/wgdev` privileged test binaries under `unshare -rn`, then `python3 tests/integration/test_daemon.py -v` |
| `go test ./internal/<pkg>/...` | One package; `go test -short ./internal/policy/...` runs a quarter of the simulation seeds |
| `go test -c -o .nftable.test ./internal/nftable && unshare -rn ./.nftable.test -test.v` | Privileged nft tests alone (same for `internal/wgdev`) |
| `python3 tests/integration/test_topology.py -v` | Namespace harness self-test (no daemon) |
| `python3 tests/integration/test_daemon.py -v` | Daemon scenarios in the namespace topology; run `make build` first |
| `python3 tools/tune.py --data DIR extract LOGDIR`, then `verify`, `paths`, `replay`/`faults`/`sim -- FLAGS`, `tune` | Offline analysis and flag tuning on a recorded debug dry-run ([docs/scoring.md](docs/scoring.md#tuning-on-recorded-data)); builds `cmd/wgsteer-replay` and the policy test binary into `DIR` |

CI (`.github/workflows/ci.yml`): `make test`, `make build` and `make integration` natively on linux/amd64 and linux/arm64 (Ubuntu 26.04) for pushes to `master` and pull requests; a `v*` tag runs `make test`, then builds release tarballs for `amd64`, `arm64` and `mips64` and publishes them as a GitHub pre-release ([docs/testing.md](docs/testing.md#ci)). 32-bit targets do not compile with the pinned nftables ([docs/caveats.md](docs/caveats.md#no-32-bit-builds)).

Test layout, host requirements and quirks: [docs/testing.md](docs/testing.md).

## Conventions

- `gofmt`, tabs; never reformat unrelated code.
- Wrap errors with `fmt.Errorf("...: %w", err)`; check with `errors.Is`/`errors.As`.
- `snake_case` file names; acronyms keep their case (`UDPAddr`, `RTT`, `ID`, `NFT`).
- Logging: stdlib `log/slog` only, stable message strings and `key=value` attributes. Never log private or preshared keys (the probe's `IpcGet`/`UAPI` text contains the private key). Log strings and keys are documented in [docs/observability.md](docs/observability.md); update it when they change.
- Imports grouped: stdlib, third-party, this module.
- No CGO. Do not run `go mod tidy` or change dependency versions (`github.com/google/nftables` must stay at a master version with `TableFlagOwner`/`AsLasting`; v0.3.0 cannot create owner tables).
- Tests are deterministic and test behavior and boundaries; privileged tests skip with a clear message outside a user+network namespace with `CAP_NET_ADMIN`.

## Invariants

Do not break these; each one exists because the alternative fails in the field.

- **Block, then set.** A switch commits the nft deny-list first, waits for the ACK (or a matching read-back), waits 1 ms (`drainDelay`: old-path packets already queued in kernel WireGuard's receive path drain), then sets the endpoint and kicks; 200 ms later a post-switch check re-reads the device and re-asserts the target if late packets roamed it back. A failed nft commit aborts the switch: the device is untouched and the engine is not committed. Never reverse the order: one late packet would roam the device back. A failed endpoint write (several netlink calls) stays pending and is redone with the peer's original keepalive until a read confirms it; never adopt the kick's temporary keepalive (0 or 1 s) as the device's, and never treat a write result as observed state (verification and endpoint handling use reads only).
- **The deny-list is dport-scoped.** Every rule is `udp dport <device listen port> ip|ip6 saddr A udp sport p counter drop`. Never emit a rule without `udp dport`: the probe shares the host and receives replies from every candidate on its own port. The listen port is dynamic; rules follow it.
- **One owner-flag table on one lasting socket.** All nft operations go through the single `AsLasting()` connection that created the table with the owner flag. An nft error never implies a lost table: a failed transaction leaves the previous rules in force and the socket open. Replace the connection only when the socket is unusable, and only after `CloseLasting()`. Never open a second connection while the first is open (it cannot modify the table, and the old socket keeps stale rules alive). Never flush the ruleset or touch other tables.
- **Roaming-disable creation order.** In the probe, `DisableSomeRoamingForBrokenMobileSemantics()` must run before the `IpcSet` that creates the peer, and that same `IpcSet` must contain `endpoint=` (wireguard-go evaluates `brokenRoaming && endpoint != nil` only at peer creation, `device/uapi.go:263`). Retarget only with `public_key=…`/`endpoint=…`; never re-create the peer outside `probe.New`.
- **The probe uses its own UDP bind.** `conn.NewDefaultBind()` is broken in the pinned wireguard-go (`conn/bind_std.go` lines 366–376, `StdNetBind.Send` corrupts IPv6 destinations after an IPv4 send; fix pending upstream as wireguard-go PR #135). Keep `udpBind` (`internal/probe/bind.go`) until a merged fix is pinned and `TestUDPBindAlternatingFamilies` passes against `conn.NewStdNetBind()`. Do not `replace` wireguard-go with a fork just to drop `udpBind`; the PR author's fork lags the pinned upstream (see [docs/caveats.md](docs/caveats.md#upstream-wireguard-go-bind-bug)).
- **fwmark copy.** The probe takes the live device's fwmark at start and follows every change seen by reconcile; the probe config must not set one. After any `SetFwmark` failure the socket marks are unknown and the device's mark is re-applied until one succeeds, even if it equals the last good one; `Probe.SetFwmark` re-applies the mark to its bind directly (wireguard-go caches a new mark before applying it and skips identical ones).
- **Aliases.** An unlisted endpoint seen on the device is an alias of the current selection: never denied, never re-asserted. On switching away, the selection and its aliases are denied until the next switch, which rebuilds the denied set from scratch; never release them early (nft counters count unauthenticated packets, and a lost kick keeps the old path delivering). A device found on a denied unlisted endpoint was roamed back by late packets: re-assert it, never learn it as the new selection's alias. A startup switch has no previous selection, so the unlisted start endpoint stays allowed and is learned as an alias of the new selection if the device keeps using it. A listed, non-selected endpoint on the device is re-asserted (not a switch, no cooldown).
- **Gated per-component comparisons with net-time accumulators.** Latency and loss are compared separately, each gated by c standard errors. Timers are net-time accumulators (+dt while the condition holds, −dt otherwise, clamped); never require a condition to hold continuously.
- **Tick proposes, Commit applies.** `Engine.Tick` never changes the selection; the daemon calls `Engine.Commit` only after the switch ran (or was simulated in dry-run). Skipping `Commit` keeps the accumulators so the switch is proposed again.
- **Policy defaults are tuned against the simulation.** `policy.DefaultParams` is the single source of the scoring defaults. Change them only with `go test ./internal/policy/...` (calibration table and behavioral targets) green, and update [docs/scoring.md](docs/scoring.md).
- **The status snapshot is the only read interface.** The loop publishes an immutable `status.Status` via `atomic.Pointer`; the SIGUSR1 dump, summaries and any future HTTP handler read only snapshots, never loop state.
- **Clocks.** The loop and policy use `CLOCK_BOOTTIME` (suspend shows up as a time gap; the wall clock may step). The watchdog uses Go's monotonic clock (suspend is not a stall). Snapshot and log times are wall time.
- **Only `CAP_NET_ADMIN`.** The daemon must keep working as a non-root user with no other capability; the namespace suite starts every daemon under `setpriv` with exactly that set (`DAEMON_PRIVILEGES`), and startup fails fast at step `privileges` without it. A change that needs another capability is a design change: document it in [docs/design.md](docs/design.md#privileges).
- **Single event loop.** Only the loop goroutine touches the engine, the nft manager, the wgctrl client and the probe; none of them is safe for concurrent use.
