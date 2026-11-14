## Motivation
Each LAPI middleware owns one `lapi.Client`, and each Client runs two background loops: the stream poll that downloads decisions and the usage-metrics push. Traefik runs the plugin under yaegi v0.16.1, which builds one case list per `select` statement and shares it across every goroutine that executes that statement. Fork #171 kept the stream and metrics loops of one Client on different statements, but every Client still ran the same `runStreamTicker`, `runMetricsTicker` and `stopTicker` statements.

With two or more LAPI middlewares, or during a reload that keeps the old Client in reclaim grace beside a new one, a loop can wait on another Client's ticker or stop channel. Reproduced under yaegi v0.16.1 on master: two stream loops on their own channels, 200 000 ticks each, `GOMAXPROCS(2)`; 5 of 5 runs failed with 2 to 12 ticks taken by the wrong loop. A crossed tick only skips or doubles one poll. A crossed stop is worse: when one Client is Slept or Closed while another waits on its channels, either the live Client takes the stop and its stream polling ends for good while `StreamHealthy` still reports true, or it stays blocked on a stopped ticker. Either way that middleware keeps serving with stale decisions and logs nothing (inferred from the shared case list; the crossed stop was not driven deterministically).

This is the multi-Client form of upstream issue https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/377 (stream stopped polling for up to ~20 minutes under yaegi with no error), which upstream fixed for the stream-versus-metrics case in PR https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/399.

Priority: P2 — real operator pain with limited blast radius: only deployments with several LAPI middlewares or reloads, and the silent stop needs a crossing at the moment another Client stops

## Implementation
Both loops now run on a `pollTimer` built on `time.AfterFunc`: the stdlib timer goroutine calls `work()`, then re-arms the timer for one interval unless the timer was stopped. Stop sets a flag under the timer's mutex and stops the stdlib timer; it does not wait for a `work()` already running. `New`, `startStream`, `Wake`, `Sleep` and `Close` hold a `*pollTimer` per loop instead of a stop channel, and `stopTicker` is gone, so `pkg/lapi` has no `select` statement left and nothing for yaegi to share between Clients. Reclaim grace already uses `AfterFunc` for the same yaegi reason. Upstream PR 399 ranges over `ticker.C` instead; that was not copied because `Ticker.Stop` does not close `C`, so the goroutine would never end after Sleep or Close. Regression tests: an AST guard that fails on master's three `select` statements; a yaegi test that runs 16 production poll timers and stops half (it proves the new loop; the master failure of the old loop is the 200 000-tick reproduction recorded in explore); and native tests for fixed delay, independent stop, stop during work, and Sleep/Wake/Close.

## What this changes
**Operators.** The next stream or usage-metrics poll now starts one interval after the previous one finished, not on a fixed-rate tick.
**Admin users.** None.
**Developers.** `pkg/lapi` non-test code must not use `select`; Client loops start with `startPollTimer` and stop with `pollTimer.stop`.
**End users.** None.

## Merge readiness
Ready for review. 0 items remain.

Priority: P2 — real operator pain with limited blast radius: only deployments with several LAPI middlewares or reloads, and the silent stop needs a crossing at the moment another Client stops
Reviewed head: c2f9fa25
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Ready |
| CI proof | 6/6 | succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/43635695457 |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-11-14-lapi-multi-client-ticker pushed | `git` |
| OpenSpec | isolate-lapi-poll-loops-across-clients | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/208 | pr-host |
| CI | build 43635695457 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/43635695457 | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/43635695457 |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_lapi_stream-single-flight](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-lapi-multi-client-ticker/openspec/changes/archive/2026-11-14-isolate-lapi-poll-loops-across-clients/proposal.md) — modified
- [core_plugin_lapi_usage-metrics](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-lapi-multi-client-ticker/openspec/changes/archive/2026-11-14-isolate-lapi-poll-loops-across-clients/proposal.md) — modified

Completed:
- [core_plugin_lapi_stream-single-flight](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-lapi-multi-client-ticker/openspec/specs/core_plugin_lapi_stream-single-flight/spec.md) — modified
- [core_plugin_lapi_usage-metrics](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-lapi-multi-client-ticker/openspec/specs/core_plugin_lapi_usage-metrics/spec.md) — modified


## Deviations from the ask
None.

## Follow-up issues
None.

## How this fits together
Ticket 2026-11-14-lapi-multi-client-ticker on branch 2026-11-14-lapi-multi-client-ticker targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/208; CI build 43635695457 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/43635695457.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Which loop shape is yaegi-safe across Clients and still stops on Sleep/Close? | bounded asked — 2 startStreamTicker + 2 startMetricsTicker + 4 stopTicker call sites in pkg/lapi, all migrated here (roots: pkg/**/*.go); Desired "Each Client's stream loop and metrics loop receives only its own ticks and its own stop" | assumed — `time.AfterFunc` poll timer with Reset after work and a stopped flag; no select in pkg/lapi. | explore |


## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-lapi-multi-client-ticker/devstate/staging/2026/11/2026-11-14-lapi-multi-client-ticker/codereview_standards.md) — 4 total, 0 pending, 4 completed
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-lapi-multi-client-ticker/devstate/staging/2026/11/2026-11-14-lapi-multi-client-ticker/codereview_nitpicks.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-lapi-multi-client-ticker/devstate/staging/2026/11/2026-11-14-lapi-multi-client-ticker/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-lapi-multi-client-ticker/devstate/staging/2026/11/2026-11-14-lapi-multi-client-ticker/codereview_scope.md) — 1 total, 0 pending, 0 completed, 1 skipped
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-lapi-multi-client-ticker/devstate/staging/2026/11/2026-11-14-lapi-multi-client-ticker/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-lapi-multi-client-ticker/devstate/staging/2026/11/2026-11-14-lapi-multi-client-ticker/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-lapi-multi-client-ticker/devstate/staging/2026/11/2026-11-14-lapi-multi-client-ticker/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-lapi-multi-client-ticker/devstate/staging/2026/11/2026-11-14-lapi-multi-client-ticker/codereview_coverage.md) — 1 total, 0 pending, 1 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 4 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | c2f9fa25ab4bd68e7b348348933c3028aae7d6c8 | Card must match the branch you measured |

### Stored data model
None.
