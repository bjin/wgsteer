# Observability

Everything an operator needs to know what the daemon saw, decided and why is in the log; the full state is in the status snapshot. Log strings and keys below are the stable interface; this file is the single place that lists them (source: `internal/daemon/*.go`, `internal/probe/probe.go`, `internal/probe/tun.go`).

## Logging basics

- `log/slog` text handler with millisecond timestamps (switch timing analysis needs them; logd keeps only seconds), on stderr by default (procd → logd, systemd → journal).
- `--log-dir DIR` writes every record only to gzip files in `DIR` instead (source: `internal/logfile`). Stderr then carries only what precedes the logger (flag errors) and the file writer's own notices (`wgsteer: log file: … (dropping records until a write succeeds)` once per failure episode, `wgsteer: log file: writing again to …`, `wgsteer: log file: retention: …`); a failed open or write never stops the daemon; records are dropped until the first record at least 10 s after the failure retries (each retry may create a file, so retries are spaced out).
  - Files: `wgsteer-YYYY-MM-DDTHH.log.gz`, the UTC hour of the wall clock when the record is written (record timestamps keep the local zone); one file per hour, a record never spans two files. `DIR` is created with 0750 if missing, files with 0640.
  - Every file is created new and holds one gzip member of one daemon run. A restart within the hour, a wall clock stepped back to an hour that has a file, or a retry after a write failure creates the hour's next file: `wgsteer-YYYY-MM-DDTHH_1.log.gz`, `_2`, … (readers order by hour, then this number). Appending is never done: a daemon killed by `SIGKILL`, a panic or a watchdog exit whose flush timed out leaves its member without a trailer, possibly mid-block, and a member written behind it would be undecodable. Such a file reads like an open one: what was flushed, then the end of the data.
  - Flush lag: the open member is sync-flushed once its oldest unflushed data is 10 s old, so a reader that decompresses the unterminated stream (`zlib.decompressobj(31)`) sees every record older than about 10 s. Rotation, a clean stop (exit 0) and a startup failure (exit 1) finish the member (gzip trailer); the watchdog exit (3) finishes it on a best-effort basis within its 1 s report wait.
  - Retention: when the first file is opened and at every rotation, files in `DIR` named exactly like log files whose hour ended more than `--log-max-age` ago (default 168h, at least 1h) are deleted. A file whose hour ended exactly `--log-max-age` ago is kept. Other files and the file being written are never touched.
  - Per-file header: every file opened by a rotation (a later hour than the previous file; not the first file of a run, which has the startup report) starts with a `config` record (same message, level and keys as the startup one, current timestamp; skipped when info records are disabled). A run therefore has several `config` records with identical values.
- `--log-level` `debug|info|warn|error` (default `info`). `SIGUSR2` toggles between the configured level and `debug` and logs `log level changed`.
- Private and preshared keys are never logged; public keys are (base64).
- Endpoint names: an endpoint's *display name* is its configured name (the `# name` comment on its line in the endpoint list) or, when unnamed, its list index in decimal; configured names are never all digits, so the two cannot collide. Its *label* is `#` + display name (`#us`, `#3`). Key `name` (display name, no `#`) follows `index` in `endpoint`, `initial selection`, `endpoint eligible`/`endpoint ineligible`, `summary`, `trace endpoint` and `switch record endpoint`. Reasons use labels. Names and default names follow the list: after a `SIGHUP` reload that renames or reorders endpoints, every later record uses the new ones (switch history keeps the names of its time).
- Value formats: endpoints `ip:port` / `[ipv6]:port`, `none` when absent; endpoint lists comma-joined (`none` if empty); counters `ip:port=packets/bytes` comma-joined; `*_ms` keys are milliseconds with microsecond precision; costs and ratios are rounded to 4 decimals (non-finite values print as `+Inf`/`NaN`); durations use Go syntax (`1.5s`); `last_handshake` is RFC 3339 or `never`.

## Startup report

Info lines in this order, before the loop starts:

| Message | Keys |
|---|---|
| `starting` | `version` (module version stamped by `go build` from git: the tag, or a pseudo-version based on the previous tag, `+dirty` with uncommitted changes; `(devel)` without VCS information, e.g. `go run`; also printed by `--version`), `revision`, `go_version`, `kernel`, `pid` |
| `config` | One key per flag: `device`, `probe_config`, `endpoints`, `probe_addr`, `target`, `probe_interval`, `probe_timeout`, `probe_size`, `probe_mtu`, `history`, `half_life`, `min_samples`, `noise_gate`, `loss_weight`, `jitter_weight`, `order_bias`, `margin`, `margin_abs`, `persist`, `cooldown`, `wait_to_restore`, `outage_epsilon`, `reconcile_interval`, `kick`, `nft_table`, `dry_run`, `log_level`, `log_dir` (empty: stderr), `log_max_age`, `summary_interval`, `watchdog` |
| `privileges` | `uid`, `euid`, `gid`, `capabilities` (effective set: `all`, `none`, or a list such as `cap_net_admin`) |
| `endpoint` (one per entry) | `index`, `name` (display name, see below), `endpoint`, `family` (`ipv4`/`ipv6`) |
| `probe config sets a persistent keepalive; the probe does not need it` (warn, optional) | `keepalive` |
| `waiting for device` (once, if not present yet) | `device`, `reason`, `poll` |
| `device` | `device`, `type` (`kernel`/`userspace`), `public_key`, `peer`, `listen_port`, `fwmark`, `keepalive`, `endpoint`, `listed`, `peers`, `last_handshake` |
| `device has more than one peer; only the probe's peer is managed` (warn, optional) | `peers`, `peer` |
| `initial selection` | `selection`, `index` (−1 without one), `name` (only when `index` ≥ 0), `reason` (`device endpoint is listed (#name)` or why there is none) |
| `nft table` | `table`, `chain`, `owner_flag`, `owner` (netlink port id), `replaced_stale`, `listen_port`, `denied` |
| `nft table skipped` (dry-run instead of `nft table`) | `reason=dry-run` |
| `probe` | `public_key`, `probe_addr`, `target`, `listen_port` (actual local port), `fwmark`, `payload_size`, `mtu` (probe device MTU), `endpoint` |
| `ready` | `eligibility_eta` (`--min-samples` × endpoints × `--probe-interval`), `endpoints`, `selection`, `dry_run` |
| `startup failed` (error) | `step` (`privileges`, `endpoints`, `probe config`, `wgctrl`, `device`, `policy`, `nft`, `probe`), `error`. Step `privileges`: `CAP_NET_ADMIN` is not effective. `EPERM` at `device`/`nft` gets a hint that `CAP_NET_ADMIN` must be held in the user namespace owning the network namespace; `EACCES` at `device` (userspace socket) a hint to run as wireguard-go's uid |

## Runtime messages

### Switching

| Message | Level | Keys |
|---|---|---|
| `switch` | info | headline keys + `nft_ms`, `block_set_gap_ms` (nft ACK to the end of the endpoint write, including the 1 ms drain wait), `drops_before`, `keepalive`, `kick` (+ `error` if setting the endpoint failed) |
| `would switch` | info | headline keys (dry-run) |
| `switch aborted` | warn | headline keys + `error`, `nft_ms` |
| `switch record endpoint` | same as headline | `switch_id` + endpoint keys (below), one line per listed endpoint |
| `switch record rule` | same as headline | `switch_id` + rule keys (below), one line per rule |
| `switch set endpoint failed` | error | `switch_id`, `to`, `error` |
| `switch verified` | info; warn if the handshake changed | `switch_id`, `endpoint`, `handshake_unchanged`, `ticks`, `drops` (counters of the denied tuples) |
| `switch not verified` | warn | `switch_id`, `target`, `observed`, `write_pending`, `ticks` |

**Headline keys**, in order:

- always: `switch_id`, `kind` (`outage`/`degrade`/`restore`/`reload`/`startup`), `from`, `to`, `reason`, `cooldown_left`, `gap`;
- the rule that fired: `rule`, plus `outage_run`, `outage_k` (outage) or `rule_value`, `rule_hold` (degrade, restore) and `restore_level` (restore);
- `cost_from`, `biased_from` (when there is a from endpoint), `cost_to`, `biased_to`;
- the target's gate: `g`, `r_lat`, `s_lat`, `r_lat_gated`, `r_loss`, `s_loss`, `r_loss_gated`, `bias`;
- `denied`, only when non-empty (not in dry-run).

### Reconcile and device

| Message | Level | Keys |
|---|---|---|
| `re-assert` | info | `observed`, `selection`, `kick` |
| `re-assert failed` | warn | `observed`, `selection`, `error` |
| `endpoint write resumed` | info | `target`, `keepalive` (the original), `attempts`, `observed`, `observed_keepalive` |
| `endpoint write retry failed` | warn on the first failed retry, then debug | `target`, `keepalive`, `failures`, `error` |
| `endpoint write superseded` | info | `target`, `keepalive`, `observed_keepalive`, `observed` (the device was reconfigured while a write was pending) |
| `alias learned` | info | `alias`, `selection` |
| `device detached` | warn | `device`, `reason` (once per reason) |
| `device attached` | info | `device`, `type`, `listen_port`, `fwmark`, `endpoint`, `peers` |
| `device has more than one peer; only the probe's peer is managed` | warn | `peers`, `peer` |
| `listen port changed` | info | `old`, `new` |
| `fwmark changed` | info | `old`, `new` |
| `probe fwmark failed` | warn once, then debug while retried | `fwmark`, `error` |
| `device handshake stale` | warn | `handshake_age`, `selection` (once per episode) |

### nft

| Message | Level | Keys |
|---|---|---|
| `nft rebuild` | info | `reason` (`listen-port`, `reload`, `retry`), `listen_port`, `denied`, `drops_before` |
| `nft error` | warn | `op` (`apply`, `reconnect`, `counters`, `close`), `reason` (`switch`, `listen-port`, `reload`, `retry`, `reconcile`; absent for `close`), `error` |
| `nft reconnect` | warn | `reason`, `table`, `owner`, `listen_port`, `denied` |
| `nft table deleted` | info | `table` |

### Probe and endpoints

| Message | Level | Keys |
|---|---|---|
| `probe session established` | info | `handshake_age` |
| `probe session expired` | info | `handshake_age` (`never` without a handshake) |
| `probe state failed` | warn | `error` (once per episode) |
| `probe send failed` | warn | `step` (`retarget`/`send`), `endpoint`, `error` (once per episode) |
| `endpoint eligible` / `endpoint ineligible` | info | `endpoint`, `index`, `name`, `samples`, `cost` |
| wireguard-go messages | debug (verbose), warn (errors) | `component=probe component=wireguard-go` |

### Lifecycle, signals, summary

| Message | Level | Keys |
|---|---|---|
| `signal` | info | `signal` (`SIGHUP`, `SIGTERM`, `SIGINT`; logged as `hangup`, `terminated`, `interrupt`) |
| `endpoints reloaded` | info | `endpoints`, `added`, `removed`, `selection_removed` (only `endpoints` while waiting for the device) |
| `reload failed` | error | `error`, `kept` (only `error` while waiting for the device) |
| `log level changed` | info (or the configured level if higher) | `level` |
| `status` | info | `row` (SIGUSR1, one record per row) |
| `summary` | info | `endpoint`, `index`, `name`, `selected`, `loss`, `rtt_mean_ms`, `rtt_std_ms`, `cost`, `valid`, `invalid`, `eligible`, `fresh`, `deny_packets` (every `--summary-interval`, one line per endpoint) |
| `stopping` | info | `signal` |
| `stopped` | info | |
| `watchdog: event loop stalled, exiting` | error (best-effort: the exit waits at most 1 s for it and, with `--log-dir`, for finishing the log file) | `stalled_for`, `limit`, `stacks` (all goroutines) |

### Debug only

| Message | Keys |
|---|---|
| `sample` | `endpoint`, `index`, `seq`, `outcome` (`reply`/`loss`/`invalid`), `rtt_ms`, `slot_start`, `finished_after_ms` |
| `unmatched reply` | `seq`, `endpoint_id`, `rtt_ms` |
| `sample ignored` | `endpoint`, `seq`, `reason` |
| `trace endpoint` | endpoint keys, one line per endpoint per tick |
| `trace rule` | rule keys, one line per rule per tick |
| `trace decision` | `switch`, `kind`, `to`, `blocker`, `reason`, `cooldown_left`, `gap` |
| `switch deferred` | `reason`, `kind`, `to` |
| `post-switch check` | (none; the extra reconcile 200 ms after a switch) |
| `device endpoint differs from simulated selection` | `observed`, `selection` (dry-run) |
| `device endpoint without selection` | `observed` |
| `probe reply dropped: reply channel full` | `seq` |

## Decision trace fields

`trace endpoint` and `switch record endpoint`:

| Key | Meaning |
|---|---|
| `endpoint`, `index`, `name`, `active` | Address, list position, display name, whether it is the selection |
| `samples`, `replies`, `invalid` | Valid samples in the window, replies among them, invalid slots so far |
| `loss`, `loss_se` | $\hat p$ and its standard error |
| `latency_ms`, `latency_se_ms` | Latency term $L$ and its standard error |
| `rtt_mean_ms`, `rtt_std_ms` | Weighted RTT mean and standard deviation |
| `loss_factor` | $F = 1 + \alpha\hat p/(1-\hat p)$ |
| `cost`, `biased_cost` | $L\cdot F$, and with the order bias |
| `g`, `r_lat`, `s_lat`, `r_lat_gated`, `r_loss`, `s_loss`, `r_loss_gated`, `bias` | Gated ratio G(active→this) = exp(`r_lat_gated` + `r_loss_gated`) · `bias` and its components, same keys as the switch headline (absent for the active endpoint or without a selection) |
| `eligible`, `fresh` | See [scoring.md](scoring.md#definitions) |
| `trailing_losses` | Loss run counted by the outage rule (restarts on a time gap and on ticks where no endpoint is fresh) |
| `restore_level` | Restore backoff level |

`trace rule` and `switch record rule`: `rule` (`outage`, `degrade`, `restore`, `startup`, `reload`), `target`, then `run`, `k` (outage) or `value`, `hold` (degrade, restore) and `level` (restore), then `active` (condition holds this tick) and `fired` (threshold reached). `value`/`hold` are the net-time accumulator and its limit.

The `reason` of `trace decision` is one sentence naming the switch or the blocking guard; the blockers are listed in [scoring.md](scoring.md#blockers). Reasons refer to endpoints by label and address (`#us 154.17.238.167:12344`, `#3 127.0.0.1:2344`).

`sample` and `trace decision` keep their key order (`tools/tune.py` parses them with order-sensitive patterns) and have no `name` key.

## SIGUSR1 dump

`SIGUSR1` logs the current snapshot as a table, one `status` record per row. Row prefixes: `daemon:`, `device:`, `selection:`, `restore levels:`, `decision:`, `rule:`, `probe:`, `endpoints:` (aligned table with header `# name endpoint family sel samples invalid loss±se latency±se ms rtt mean/std ms cost biased G eligible fresh run level last sample denied`), `nft:`, `nft deny:`, `history:` (count plus the last 5 events). The `selection:` row starts with the selection's label and address (`#us 154.17.238.167:12344`, `none` without one), the `probe:` row's `slot=` with the slot endpoint's label (`#unlisted` for a slot that straddled a reload removing it). Switch IDs (`history: #12`) are not endpoint labels.

## Status snapshot

`internal/status.Status`, rebuilt after every handled loop event (except a bare probe reply) and published atomically. It is the only read interface: the SIGUSR1 dump and the summary read it; a future read-only HTTP endpoint would serve it as JSON. It is JSON-tagged; no JSON output ships yet.

- All times are wall-clock times (converted from the loop clock). Durations are nanoseconds in JSON.
- `netip` values marshal as strings; zero addresses are omitted (`omitzero`).
- Estimator values (`policy.Float`) are numbers when finite and the strings `"+Inf"`, `"-Inf"`, `"NaN"` otherwise.

| Path | Fields |
|---|---|
| (root) | `at`, `daemon`, `device`, `selection`, `probe`, `endpoints[]`, `nft`, `history[]` (oldest first, at most 50) |
| `daemon` | `version`, `revision` (omitempty), `go_version`, `pid`, `start_time`, `state` (`waiting-device`, `running`, `detached`, `stopping`), `dry_run` |
| `device` | `name`, `present`, `type`, `public_key` (both omitempty), `peer`, `listen_port`, `fwmark`, `endpoint`, `listed`, `alias`, `keepalive`, `last_handshake`, `handshake_age`, `rx_bytes`, `tx_bytes` |
| `selection` | `endpoint`, `index` (−1 without one), `name` (display name; omitted without a selection), `since`, `reason`, `removed`, `aliases[]`, `cooldown_left`, `rules[]`, `restore_levels[]` (`endpoint`, `level`; nonzero only), `decision`, `last_switch` (a history event, omitempty), `verified` (omitempty while pending or without a switch) |
| `selection.decision` | `at`, `switch`, `kind`, `to`, `blocker`, `reason` |
| `selection.rules[]` | `rule`, `target`, `value`, `hold`, `level`, `k`, `run` (all omitempty), `active`, `fired` |
| `probe` | `public_key`, `probe_addr`, `target`, `listen_port`, `fwmark`, `session_valid`, `last_handshake`, `session_age`, `slot`, `rx_bytes`, `tx_bytes` |
| `probe.slot` | `endpoint`, `index`, `name` (display name; omitted when no longer listed), `seq`, `start`, `valid`, `pending` |
| `endpoints[]` | `addr`, `index`, `name` (display name), `active`, `samples`, `replies`, `invalid`, `loss`, `loss_se`, `rtt_mean`, `rtt_std`, `latency`, `latency_se`, `loss_factor`, `cost`, `biased_cost`, `eligible`, `fresh`, `gate`, `trailing_losses`, `restore_level`, `last`, `last_invalid`, `family`, `denied`, `deny_packets`, `deny_bytes` |
| `endpoints[].gate` | `g`, `r_lat`, `s_lat`, `r_lat_gated`, `r_loss`, `s_loss`, `r_loss_gated`, `bias` (omitted for the active endpoint) |
| `endpoints[].last` | `at`, `replied`, `rtt` |
| `nft` | `enabled` (false in dry-run), `table`, `chain`, `owner_flag`, `owner`, `listen_port`, `denied[]` (`endpoint`, `packets`, `bytes`), `in_sync`, `last_error`, `last_error_at` |
| `history[]` | `id`, `at`, `kind`, `from`, `to`, `result` (`ok`, `set-failed`, `aborted`, `dry-run`), `error`, `reason`, `block_set_gap`, `denied[]`, `record` |
| `history[].record` | `at`, `active`, `removed`, `gap`, `cooldown_left`, `endpoints[]` (endpoint view without the deny fields), `rules[]` |

Latency values (`rtt_mean`, `rtt_std`, `latency`, `latency_se`, `cost`, `biased_cost`) are milliseconds.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Clean stop (`SIGTERM`/`SIGINT`), `-h`/`-help` or `--version` |
| 1 | Invalid flags (message `wgsteer: <error>` on stderr) or a startup failure (`startup failed`) |
| 3 | Watchdog: the event loop stalled longer than `--watchdog` |
