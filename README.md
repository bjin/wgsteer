# wgsteer

A Linux daemon that keeps one WireGuard client peer on the best of several equivalent UDP endpoints. Each candidate (a relay `ip:port`, `[ipv6]:port`, or the server's own address as the last fallback) must reach the same server `ip:port`, so the session survives every switch without a handshake. The daemon measures every candidate continuously, switches the live device's peer endpoint when the current one is significantly worse (or down), returns to earlier-listed endpoints once they are no longer worse, and blocks roaming back with an nftables deny-list.

## How it works

- **Probe:** an embedded wireguard-go device with its own WireGuard identity (registered on the server as a separate peer) sends one ICMP echo through the tunnel per `--probe-interval`, round-robin over the candidates. Roaming is disabled on the probe, so each reply is attributed to the endpoint it was sent through. RTT and loss are measured end to end through a real WireGuard path.
- **Scoring:** per endpoint, a recency-weighted estimate of loss, RTT mean and jitter gives a cost ("effective RTT"). Endpoints are compared through a noise-gated ratio with net-time accumulators, so noise and single losses do not cause switches. Rules: outage, degradation, restore to an earlier endpoint, plus cooldown and backoff. See [docs/scoring.md](docs/scoring.md).
- **Switch:** first commit an nft rule set that drops UDP from every other listed candidate to the device's listen port, then set the peer endpoint and force a keepalive. The table is owned by the daemon's netlink socket, so the kernel removes it whenever the daemon exits, however it exits. See [docs/switching.md](docs/switching.md).

## Requirements

- Linux >= 5.12 (nftables owner-flag tables). No `nft` or `wg` binary is needed at runtime.
- `CAP_NET_ADMIN`, and no other capability (wgctrl reads and writes, nftables, `SO_MARK`); also for `--dry-run`. Runs as a non-root user holding it; startup logs the effective capabilities and fails fast without it. Service-manager setups, including OpenWrt procd: [docs/design.md](docs/design.md#privileges).
- A WireGuard device (kernel or userspace) whose peer for the server is the managed peer. Other peers are left alone (startup logs a warning).
- Go 1.26 or newer to build.

## Build

```sh
make build          # ./wgsteer (static, CGO_ENABLED=0)
make build-arm64    # ./wgsteer-arm64
```

## Usage

```sh
wgsteer \
  --device wg0 \
  --probe-config /etc/wgsteer/probe.conf \
  --endpoints /etc/wgsteer/endpoints \
  --probe-addr 192.0.2.3 \
  --target 192.0.2.1
```

| Flag | Meaning |
|---|---|
| `--device` | Live WireGuard device |
| `--probe-config` | Probe identity in WireGuard xplatform UAPI `set` format (hex keys) |
| `--endpoints` | Candidate list, earlier lines preferred |
| `--probe-addr` | The probe's tunnel address (source of the probe ICMP); it need not be assigned to any interface |
| `--target` | The server's tunnel address (ICMP destination); same family as `--probe-addr` |

All tunables and their defaults: `wgsteer -h`. Start with `--dry-run` for a while to see what it would do: it probes, scores and logs `would switch` decisions but never touches the device or nftables.

Endpoint list (`--endpoints`): one literal endpoint per line, `#` comments and blank lines allowed. IPv6 needs brackets; hostnames, zones, link-local, IPv4-mapped, unspecified and multicast addresses, port 0 and duplicates are rejected.

```
# preferred first
203.0.113.10:443
198.51.100.20:51820
[2001:db8::30]:443
# direct to the server, last resort
203.0.113.1:51820
```

Probe config (`--probe-config`): UAPI `set` keys with hex-encoded keys and exactly one peer, the same server the live device talks to. Blank lines and `#` lines are allowed.

```
private_key=<probe private key, 64 hex digits>
public_key=<server public key, 64 hex digits>
allowed_ip=192.0.2.1/32
```

- Optional: `listen_port`, `preshared_key` (the one registered for the probe peer on the server), `replace_peers=true`, `replace_allowed_ips=true`, `protocol_version=1`.
- `allowed_ip` defaults to the target's host route and must contain `--target`.
- `endpoint` is overridden (the probe retargets every slot); `persistent_keepalive_interval` is accepted but unnecessary (warning); `fwmark` is rejected (it is copied from the live device).
- UAPI has no MTU key: the probe device's MTU is `--probe-mtu` (default 1420). Set it to the live device's MTU, with `--probe-size` up to `--probe-mtu` − 28 (IPv4 tunnel addresses) or − 48 (IPv6), to probe with full-size packets.
- The probe key must differ from the device's own key. Convert a base64 key to hex with `echo '<base64 key>' | base64 -d | od -An -v -tx1 | tr -d ' \n'`.

## Server prerequisites

- Register the probe's public key as a separate peer with its own `/32` (or `/128`), e.g. `allowed-ips 192.0.2.3/32`. Never reuse the client's key.
- The server answers ICMP echo from the probe address (no firewall drop).
- Roaming stays enabled (the WireGuard default): the server follows the client to whichever candidate it uses.
- Every candidate endpoint reaches the same server `ip:port`.

## Signals

| Signal | Effect |
|---|---|
| `SIGHUP` | Re-read the endpoint list (the probe config needs a restart) |
| `SIGUSR1` | Log the status snapshot as a table |
| `SIGUSR2` | Toggle between the configured log level and debug |
| `SIGTERM`, `SIGINT` | Clean stop: delete the nft table, close the probe; the device keeps its endpoint |

There is no control API. To inhibit steering or pin an endpoint, stop the service (a clean stop deletes the table, so the device behaves like plain WireGuard), then use `wg set` as needed. While the daemon runs, a manual `wg set` to a listed endpoint is reverted.

Exit codes: 0 clean stop, 1 invalid flags or startup failure, 3 watchdog (event loop stalled). A restart policy is required: after any unexpected exit the device keeps working unmanaged until the daemon is restarted.

## systemd

```ini
[Unit]
Description=WireGuard endpoint steering for wg0
After=network-online.target
Wants=network-online.target

[Service]
User=wgsteer
Group=wgsteer
ExecStart=/usr/local/bin/wgsteer \
  --device wg0 \
  --probe-config /etc/wgsteer/probe.conf \
  --endpoints /etc/wgsteer/endpoints \
  --probe-addr 192.0.2.3 \
  --target 192.0.2.1
ExecReload=/bin/kill -HUP $MAINPID
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
NoNewPrivileges=yes
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
```

The probe config holds a private key: make it readable only by root and the service group (`0640 root:wgsteer`). The daemon waits for the device if it does not exist yet.

## Documentation

- [docs/design.md](docs/design.md): architecture, event loop, packages, lifecycle, dry-run, privileges, clocks
- [docs/scoring.md](docs/scoring.md): estimator, cost model, decision rules, tuned defaults, calibration and simulation results, tuning flags on a recorded dry-run (`tools/tune.py`)
- [docs/switching.md](docs/switching.md): nft owner table, deny-list, error handling, switch procedure, reconcile, aliases
- [docs/observability.md](docs/observability.md): log messages, startup report, decision trace, status snapshot, exit codes
- [docs/caveats.md](docs/caveats.md): known limits, upstream wireguard-go bind bug
- [docs/testing.md](docs/testing.md): unit, integration and namespace test suites

## License

MIT, see [LICENSE](LICENSE).
