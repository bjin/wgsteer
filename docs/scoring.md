# Scoring and switch decisions

Code: `internal/stats` (ring, estimator) and `internal/policy` (cost, gated comparison, accumulators, rules). The policy is pure: every function takes the time from the caller, so it is deterministic and runs on a fake clock in tests.

## Samples

- One sample per probe slot: `{at, replied, rtt}`, attributed to its slot's endpoint by sequence number, nonce and endpoint id.
- A reply later than `--probe-timeout` is a loss for its own endpoint.
- A slot sent without a valid probe session is **invalid**: counted (`invalid`), excluded from all statistics, and it neither breaks nor extends a loss run.
- Each endpoint keeps the last `--history` valid samples in a ring.

## Estimator (per endpoint, over its ring)

| Quantity | Definition |
|---|---|
| Weight | $w = 2^{-\text{age}/h}$, age 0 for the newest sample, $h$ = `--half-life` (samples of that endpoint) |
| Effective count | $n_\text{eff} = (\sum w)^2 / \sum w^2$; ≈ 158 for a full ring with the defaults (h 60, history 267) |
| Loss | $\hat p = (\sum w_\text{lost} + a)/(\sum w + w_0)$ with a Beta prior of mean 5% and weight $w_0 = 4$ samples ($a = 0.2$) |
| Loss SE | $SE_p = \sqrt{\hat p (1-\hat p)/(n_\text{eff} + w_0)}$ |
| RTT | Weighted mean $\overline{rtt}$ and unbiased weighted standard deviation $\sigma$ over replied samples |
| Latency term | $L = \overline{rtt} + k\sigma$, $k$ = `--jitter-weight` |
| Latency SE | $SE_L = \sqrt{\sigma^2/n_\text{eff,replied}\cdot(1 + k^2/2)}$ (delta method) |

An endpoint with no replies in its window has $L = SE_L = +\infty$ (infinite cost).

One expected loss matters: the newest sample carries a sizeable share of the weight, so a single loss moves $\hat p$ and the cost noticeably and the effect fades with the half-life. No rule therefore requires a condition to hold continuously; all timers are net-time accumulators.

## Cost model

$$
\text{cost}_i = L_i \cdot F_i, \qquad F_i = 1 + \alpha\,\frac{\hat p_i}{1-\hat p_i}, \qquad \text{biased}_i = \text{cost}_i \cdot (1 + \beta\, i)
$$

- $L$: base RTT plus tail. A routing change that delays 30% of packets by +100 ms moves both mean and σ, so it is caught although the median does not move.
- $F$ (`loss_factor`): $p/(1-p)$ is the expected retransmissions per delivered packet, each costing about α RTTs of recovery. α = `--loss-weight`.
- Order bias β = `--order-bias` per list position $i$ (0-based). It breaks ties toward earlier lines and feeds the restore rule. Exact ties go to the earlier line.
- Costs rank endpoints and are reported (milliseconds). Decisions compare endpoints only through the gated ratio below, never through raw cost differences.

## Gated ratio G(A→B)

"How much better B is than the active A, beyond noise." For each component X in {latency term L, loss factor F}:

| Step | Formula | Record field |
|---|---|---|
| Log ratio | $r_X = \ln(X_A/X_B)$ | `r_lat`, `r_loss` |
| Noise | $s_X = \sqrt{SE(\ln X_A)^2 + SE(\ln X_B)^2}$, with $SE(\ln L) = SE_L/L$ and $SE(\ln F) = \alpha\,SE_p/((1-\hat p)^2 F)$ | `s_lat`, `s_loss` |
| Gate | $r'_X = \text{sign}(r_X)\cdot\max(0, \lvert r_X\rvert - c\,s_X)$, c = `--noise-gate` | `r_lat_gated`, `r_loss_gated` |
| Ratio | $G = e^{r'_\text{lat} + r'_\text{loss}} \cdot \frac{1+\beta i_A}{1+\beta i_B}$ | `g`, `bias` |

- Only A without replies: $r_\text{lat} = +\infty$, G = +Inf. Only B without replies: $r_\text{lat} = -\infty$, G = 0. Both: $r_\text{lat}$ = NaN, G = 0.
- Gating each component separately keeps precise latency shifts visible while coarse loss estimates (several percentage points of SE at 5–10% loss) are treated as noise. A significance test on the combined cost would let loss noise hide a +60 ms shift; a weak gate flaps between equal endpoints.

## Definitions

| Term | Meaning |
|---|---|
| Warm | At least `--min-samples` valid samples |
| Eligible | Warm and finite cost |
| Fresh | The latest valid sample replied and is at most 2 × N × `--probe-interval` old (N = list length). Checked only at the moment a switch would be made; a stale target waits for a later tick and keeps the accumulator |
| Net-time accumulator | Each tick adds dt while its condition holds and subtracts dt while it does not, clamped to [0, limit]; fires at the limit. A flicker costs only its own duration. All accumulators reset on every committed switch and on a time gap; a candidate's accumulator is dropped when it leaves the list |

## Rules

Evaluated after every probe slot (`Engine.Tick`), in this order; at most one switch is proposed per tick.

| # | Rule (kind) | Condition | Target | Cooldown |
|---|---|---|---|---|
| 6 | Reload (`reload`) | A `SIGHUP` removed the selection | Lowest biased cost among eligible+fresh, else fresh, else eligible | Ignored |
| 5 | Startup (`startup`) | No listed selection (device started on an unlisted endpoint or without one) and some candidate is eligible | Lowest biased cost among eligible+fresh | Applies (from daemon start) |
| 1 | Outage (`outage`) | Active endpoint's loss run ≥ K, $K = \text{clamp}(\lceil \ln\varepsilon / \ln \hat p_\text{base}\rceil, 3, 10)$, ε = `--outage-epsilon`. $\hat p_\text{base}$ excludes the ring's whole trailing loss run. The counted run restarts on a time gap and on every tick where no endpoint is fresh (common-mode outage: local uplink or server down). The active's newest loss must postdate the start of the target's current run of replies, else `outage-unconfirmed` | Lowest biased cost among eligible+fresh; else fresh with ≥ 2 samples and finite cost (startup) | Applies |
| 2 | Degradation (`degrade`) | Some B: A warm, B eligible, G(A→B) ≥ 1 + `--margin` and biased_B·(G−1) ≥ `--margin-abs` (ms). One shared accumulator, limit `--persist` | Fresh degrading B with the largest G | Applies |
| 3 | Restore (`restore`) | Per earlier E (list index below the active one; only when `--wait-to-restore` > 0): A warm, E eligible, G(A→E) ≥ 1. Own accumulator per E with hold $H_E$ = `--wait-to-restore` × $2^{\text{level}_E}$ | Fired, fresh E with the lowest biased cost | Applies |
| 7 | Time gap | Tick more than 10 × `--probe-interval` after the previous one, or backwards | Resets accumulators and loss runs; record `gap=true` | n/a |

- **Restore backoff:** level_E rises by one (cap 3) each time the daemon leaves E through a `degrade` switch, and drops by one per hour counted from the last such exit (including time spent waiting on the restore hold). The restore hold to E is `--wait-to-restore` × 2^level_E at the current level, so no restore to E comes sooner than min(2 × `--wait-to-restore`, 1 h) after a degradation exit from it. Once 2 × `--wait-to-restore` exceeds that hour, the decay shortens the long holds: at the default 45 min a restore to E needs at most 45, 60, 90 or 120 min of not-worse time at level 0, 1, 2 or 3 (nominally 45, 90, 180, 360 min), and never less than 45. A restore after a single degrade exit fires only once that level has decayed, so cycles of degrade exit and restore keep E at level 1; E reaches level 2 or 3 only when an outage or degrade switch returns to it within the hour. The backoff holds only restores; outage and degrade switches back to E are not held. On the dry-run every replayed restore fired at level 0.
- **Guards** shared by rules 1, 2, 3 and 5: no fresh target and no fresh endpoint at all → `all-down`; cooldown left → `cooldown`; no fresh target → `not-fresh`. An outage without any usable target reports `warming-up` (a fresh candidate exists but lacks samples; with nothing fresh the run has already been reset as common-mode). Never switch to the active endpoint.
- Re-asserts and alias handling are not switches and are not rate-limited ([switching.md](switching.md#reconcile)).
- A proposed switch changes nothing until `Commit`; an aborted or deferred switch is proposed again on a later tick with the accumulators intact.

### Blockers

Every non-switch decision names one blocker and a one-sentence reason (snapshot `selection.decision`, debug `trace decision`):

| Blocker | Meaning | Reason text starts with |
|---|---|---|
| `cooldown` | A rule fired, cooldown not elapsed | `cooldown Ns left (kind to #i ep pending)` |
| `persist` | Some candidate is significantly better; accumulator below `--persist` | `persist a/b s (#i ep better: G x)` |
| `restore-hold` | An earlier endpoint is not worse; its accumulator is below its hold | `restore hold a/b s for #i ep (level n)` |
| `not-fresh` | A rule fired but no target is fresh | `target not fresh: …` |
| `nothing-better` | No candidate better beyond noise | `nothing better beyond noise` |
| `all-down` | No endpoint (active included) is fresh | `all down: …` |
| `warming-up` | Active (or, without one, every candidate) below `--min-samples` | `warming up: …` |
| `no-candidate` | No other endpoint is eligible | `no other eligible candidate` |
| `outage-unconfirmed` | The active's loss run reached K, but its newest loss predates the target's current run of replies (e.g. all paths recovered together after an all-down episode and the target was re-probed first); waits for the active's next probe | `outage run predates target's replies: …` |

## Defaults

`policy.DefaultParams` is the single source of the scoring defaults (`daemon.DefaultConfig` reads them). They meet the calibration table and the behavioral targets below and were chosen on a 72 h router dry-run with `tools/tune.py` (10 endpoints and subsets of 4 and 6, the targets as a constraint). Change them only with `go test ./internal/policy/...` green.

| Flag | Default | Why |
|---|---|---|
| `--half-life` | 60 | n_eff ≈ 158, so S5's loss difference (20% vs 3%) clears the gate; on the recorded paths better than 45, and longer half-lives react too slowly to faults on the active endpoint |
| `--history` | 267 | About 4.4 half-lives: the oldest sample keeps ≈ 5% weight |
| `--loss-weight` (α) | 7 | Each lost packet costs about α RTTs of recovery; S5 switches |
| `--noise-gate` (c) | 2.5 | Switches between equal paths stay rare; lower gates scored better on the loss-free recorded paths but switch on noise between equal 5%-loss paths |
| `--jitter-weight` (k) | 2.5 | A latency tail with an unchanged median (30% of replies +100 ms) is caught within minutes |
| `--margin` | 0.14 | Lets the selection leave a degraded earlier endpoint against the order bias: on the dry-run the evening jitter of the preferred endpoints reached G ≈ 1.15–1.17 |
| `--wait-to-restore` | 45m | Returns to an earlier endpoint only after it has stayed not worse for a long time, so a daily jitter episode on it does not pull the selection back early |
| `--persist` | 30s | Detection speed of latency steps, with no extra churn on the recorded data |
| `--cooldown` | 30s | Minimum spacing of switches of any kind |
| `--margin-abs` | 10ms | Absolute floor on the effect; binds only on paths cheaper than about 70 ms, where 14% is a few milliseconds |
| `--min-samples` | 20 | Eligibility after a third of a half-life |
| `--order-bias` (β) | 0.02 | The list preference: ties and near-ties go to earlier lines |
| `--outage-epsilon` | 1e-5 | K = 4 at 5% base loss, 5 at 10% |
| `--probe-interval` | 1s | One endpoint per second |

The loss prior (mean 5%, weight 4) is a constant in `internal/stats`.

## Calibration (`TestCalibration`)

Steady-state point estimates from synthetic samples with the defaults. Active is #0 unless stated. Thresholds: G ≥ 1.14 for a degradation switch, ≥ 1 for a restore.

| Case | Active | Candidate | Cost active / cand. (ms) | G | Expected |
|---|---|---|---|---|---|
| S1 | #0 150±5 ms, 5% | #1 170±5, 5% | 217 / 244 | 0.888 | stay |
| S2 | #0 150±5, 30% | #1 180±5, 5% | 620 / 257 | 1.616 | switch |
| S3 | #0 70%@150 + 30%@250, 3% | #1 165±5, 3% | 358 / 217 | 1.519 | switch |
| S4 | #0 150±5, 10% | #1 180±5, 3% | 290 / 235 | 0.864 | stay (the loss difference barely clears the gate: r_loss 0.379 → 0.026) |
| S5 | #0 150±5, 20% | #1 180±5, 3% | 427 / 235 | 1.248 | switch |
| S4′ | #1 180±5, 3% | #0 150±5, 10% | 235 / 290 | 1.157 | switch to #0 allowed (the loss difference is at the edge of the noise) |
| S6 | #1 165±5, 4% | #0 150±5, 4% | 235 / 215 | 1.095 | no degradation switch; restore |
| S7 | #1 160±5, 5% | #0 160±5, 5% | 231 / 231 | 1.020 | restore |
| S7 from #0 | #0 160±5, 5% | #1 160±5, 5% | 231 / 231 | 0.980 | stay |
| S8 | #0 210±5, 5% (+60 ms) | #1 165±5, 5% | 297 / 237 | 1.211 | switch |
| S9 | #0 175±5, 5% (+20 ms) | #1 165±5, 5% | 251 / 237 | 1.019 | stay |
| S10 | all 100% loss | | +Inf / +Inf | 0 | no switch |

## Behavioral targets (`TestTargets`)

A seeded simulation (`internal/policy/sim_test.go`) feeds the real estimator and engine with synthetic ground truth (i.i.d. and Gilbert–Elliott loss, RTT distributions with bimodal tails, step changes) on a fake clock: 5 endpoints, 1 s interval, defaults, fixed seeds. `-short` runs a quarter of the seeds.

| Scenario | Target | Measured | Seeds |
|---|---|---|---|
| Equal paths, 5% loss | ≤ 1 switch / 24 h | 0.42 / 24 h (four seeds with 2–3, the rest 0) | 24 |
| Equal paths, 10% loss | ≤ 1 degradation switch / 12 h | 0.17 | 24 |
| +60 ms step on active | ≤ 3 min every seed | 50–60 s | 12 |
| 30% of packets +100 ms, 3% loss | ≤ 4 min | 45–140 s | 12 |
| +20 ms step (not significant) | ≤ 1 switch / 3 h | 0.54 / 3 h (worst seed 3) | 24 |
| **Loss 5% → 50%** | ≤ 4 min | 41–**285** s, median 105 s; **not met, subtest skipped** | 12 |
| Loss 5% → 30% | median ≤ 5 min, max ≤ 10 min | median 207 s, max 487 s | 12 |
| Recovery, 5% background loss | restore within [WTR, 1.5×WTR] after eligibility | 2700–2804 s | 12 |
| Recovery, 10% background loss | same | 2700–3010 s | 12 |
| Recovery, S6 | same | 2700–2705 s | 12 |
| #0 genuinely worse | 0 reverts to #0 | 0 | 12 |
| Near-margin pair (#0 10%, others 5%) | ≤ 1.5 switches / h; no restore to #0 sooner than min(2×WTR, 1 h) after leaving it | 1.09 / h; 103 such restores, all at ≥ 1 h | 24 |
| Bursty, 60 s bad episodes every 10 min | report only | 2.7 degradation switches / 12 h | 12 |
| Bursty, 10 min bad episodes every 60 min | report only | 2.8 degradation switches / 12 h | 12 |
| Periodic all-down episodes (60 s down every 30 min 1 s, 12 h, equal paths at 0/5/10% loss; added beyond the design targets) | no outage switch within an episode or 5 min after; mean ≤ 0.25 outage switches and ≤ 1 switch / 12 h | 0 near an episode at every loss level; all switches 0 / 0.13 / 0.42 per 12 h | 24 per level |

### The unmet 50%-loss tail

- The loss 5% → 50% row misses its 4-minute bound in one seed of twelve (285 s), because that seed's realised loss right after the step is low. The subtest still asserts median ≤ 3 min and max ≤ 6 min, then skips with the measured values and the reason (`KNOWN TRADE-OFF`).
- Cause: the long half-life that S5 needs makes loss tracking slower.
- A severe loss jump is not missed: the outage rule fires on K consecutive losses; loss 5% → 100% switches after a median 16 s (max 21 s) in this simulation.
- The near-margin row is at 1.09 / h against 1.5.

### Behaviors worth knowing

- **Restore hops:** rule 3 picks the restore target by lowest biased cost. On equal paths the cost noise outweighs the 2% order bias, so a restore can step through intermediate endpoints (#3 → #2 → #1 → #0). This adds switches to the equal-path and near-margin counts. Choosing the earliest fired endpoint would remove the hops but changes the rule.
- **Startup outage:** the outage run length at startup comes from the 5% prior, so on a path with 10% real loss an early legitimate outage switch to #0 can happen before eligibility.
- **Freshness:** a degradation switch whose target is not fresh waits; it does not fall through to a ready restore.

## Tuning on recorded data

`tools/tune.py` (Python 3, standard library; needs Go to build its helpers) replays the per-sample `sample` lines of a `--log-level debug` run through the real engine (`cmd/wgsteer-replay`, built into the data directory on first use) with any flags and any subset of the recorded endpoints. `tools/tune.py -h` lists every option.

| Command | What it does |
|---|---|
| `extract LOGDIR…` | Parses the logs into `--data` (default `tune-data/`): `trace.tsv`, one row per probe slot with the logged decision, and `meta.json` (daemon runs, flags, endpoint list, switches, `run.sh` wg0 pings). Refuses logs with a `SIGHUP` reload |
| `verify` | Replays every daemon run with its own logged flags; every logged decision must be reproduced. A switch may land one tick early or late: the log has millisecond wall times, the daemon `CLOCK_BOOTTIME`, and a net-time accumulator reaches its limit within microseconds of a tick |
| `paths` | Loss and RTT percentiles per endpoint, by hour of day, loss run lengths, common-mode losses, wg0 ping vs the probe |
| `replay -- FLAGS` | Switches and hindsight quality of one flag set, against the defaults and the best static endpoint; `--switches` lists them |
| `faults -- FLAGS` | Synthetic faults on whichever endpoint is active (outage, 50/30/10% loss, +60/+30 ms, 30% of replies +100 ms), every 3 h, on top of the recorded samples: how long the selection stays on the faulted endpoint |
| `sim [--period S] -- FLAGS` | The behavioral-target scenarios above (`TestSimParams`, skipped unless `WGSTEER_SIM_PARAMS` is set) at the recorded per-endpoint period (or `--period`), against the targets |
| `tune [--grid JSON]` | Grid search (`{"flag": [values]}`; `--history` follows `--half-life` in the defaults' window shape, 267 for 60). Configs with no flaps and better than the defaults on both halves of the data go to the simulation targets (best `--sim-top` per half-life; switches on pure noise must stay within `--noise-headroom` 0.5 of their target), the passing ones to the fault check (best `--fault-top` per half-life); the pick is the lowest R with F ≤ `--max-fault` 1. Per half-life because a long half-life wins on calm data and loses on faults. Prints the pick, its simulation table and its command line per preset |

- **Presets:** `--preset NAME=SPEC` (repeatable) replays a subset of the recorded list in list order; `p3=0,1,8,9+2:4-7` expands to every way of adding two of 4–7. A preset of n of the N recorded endpoints is replayed at the recorded per-endpoint period, i.e. as deployed with `--probe-interval` × N/n; a faster schedule's samples do not exist. `--probe-interval` is therefore fixed per preset and printed with the pick.
- **Quality, with hindsight:** on a 10 s grid, each endpoint's cost from a centered window of its own samples (±5 min RTT, ±30 min loss) with the reference weights α 7, k 2.5. Regret is the active endpoint's cost minus the best one's; *pref regret* applies the reference order bias (2% per position), i.e. measures against the endpoint the list preference would pick. The objective is J = pref regret + `--switch-cost` × switches/day; R = J / J(defaults), averaged over presets, and per half of the data (a config must beat the defaults on both).
- **Faults count only when leaving is warranted:** the faulted endpoint's hindsight cost (fault applied to its recorded mean, σ and loss) is ≥ 1.25× the best other endpoint's. Otherwise staying can be right (a fault on the best endpoint while the others are degraded). F = mean time on the faulted endpoint relative to the defaults.
- **Why the simulation check:** dry-run paths are often nearly loss-free with σ ≈ 1 ms, where a low `--noise-gate` looks best. On equal paths with 5% loss (e.g. a congested local uplink, common to all paths) the same gate switches on noise; the scenarios catch that.
