Developer review: ready for review — 2026-09-06T15:43:34Z

## What this changes
**Operators.** None. `httpTimeoutSeconds` (default 10) now also bounds each LAPI request context; watch `crowdsec stream became unhealthy` if polls time out.

**Admin users.** None.

**Developers.** `lapi.Client` TryLock-skips overlapping stream polls (skip is not success). `crowdsecQuery` uses a request context deadline from `http.Client.Timeout` and does not read a nil response on transport error. Tests in `pkg/lapi/client_stream_poll_test.go`. Specs folded into `core_plugin_middleware_instance-reclaim` and `core_plugin_lapi_connection`.

**End users.** Newly banned IPs should reach the Traefik cache on the next successful poll instead of a silent multi-minute stream gap.

## Motivation
On `master`, overlapping ticker/`Wake` goroutines can treat a lease hit as a successful poll while another GET is still in flight, and a hung stream call can stall decision updates while metrics keep posting. New bans then miss the Traefik cache until the poller recovers.

## Merge readiness
Ready for review. 0 items remain.

Priority: P2 — real operator pain (stale ban cache during freeze) with limited blast radius (Traefik keeps serving).
Reviewed head: 46127c9
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | CI succeeded; no open PR comments |
| CI proof | 6/6 | Main + both e2e jobs succeeded |
| Local tests proof | N/A | Remote CI covers |
| Review resolution | N/A | No PR comments inventoried |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-upstream-377-stream-poll-freeze pushed | git push |
| OpenSpec | serialize-stream-poll archived | openspec/changes/archive/2026-09-06-serialize-stream-poll/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/42 | GitHub MCP |
| CI | build 34043057118 success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34043057118 | Main Process; e2e 34043057152 success |
| Local tests | passed | `go test ./pkg/...` |
| PR comments | no comments | comments.md absent |

## Specs
- [core_plugin_middleware_instance-reclaim](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-377-stream-poll-freeze/openspec/changes/archive/2026-09-06-serialize-stream-poll/proposal.md) — modified
- [core_plugin_lapi_connection](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-377-stream-poll-freeze/openspec/changes/archive/2026-09-06-serialize-stream-poll/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
Local upstream #377 → PR #42 → `serialize-stream-poll` applied and archived → CI green on 46127c9.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| What maps to the reporter’s exact ~20 minute gap with no `handleStreamCache:updated` lines? | assumed — native Go already bounds `crowdsecQuery` with `http.Client.Timeout`. The gap matches a ticker blocked on work (upstream sync ticker, or Yaegi not firing the timer) plus a transport stall, not a product constant. Do not bake 20 minutes. Keep `go work()`, TryLock skip, and a request context deadline. | explore |
| TryLock skip or mutex-wait single-flight? | assumed — TryLock skip. Waiting would queue `go work()` goroutines behind a hung poll. Skip must not count as success. Redis lease-hit after owning the slot still counts as success. | explore |
| Add `context.WithTimeout` when `http.Client.Timeout` already works in native Go? | assumed — yes. One request deadline from `HTTPTimeoutSeconds`. Cheap, testable, and covers Do paths that might otherwise hang after headers. Do not add Yaegi-specific workarounds. | explore |

## Before merge
None.

## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-377-stream-poll-freeze/devstate/2026/09/2026-09-06-upstream-377-stream-poll-freeze/codereview_standards.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-377-stream-poll-freeze/devstate/2026/09/2026-09-06-upstream-377-stream-poll-freeze/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-377-stream-poll-freeze/devstate/2026/09/2026-09-06-upstream-377-stream-poll-freeze/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-377-stream-poll-freeze/devstate/2026/09/2026-09-06-upstream-377-stream-poll-freeze/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-377-stream-poll-freeze/devstate/2026/09/2026-09-06-upstream-377-stream-poll-freeze/codereview_dead.md) — 0 total, 0 pending, 0 completed

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 2 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 46127c9286e030849ebde446799b1ac98f1f1aae | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: TryLock skip plus a request deadline, leaving async ticker work — versus `master`, where overlapping polls treat a lease hit as success.

Do we have a high-confidence way to reproduce? Yes for in-process overlap (`TestHandleStreamTicker_SkipDoesNotClearFailure`). No for the exact 20-minute freeze in native Go (`TestCrowdsecQuery_TimeoutBoundsHungLAPI` returns in ~1s).

Is this the best way to solve the issue? Yes versus `master` — serialize without blocking the ticker.

### Evidence
What I checked:
- `go test ./pkg/...` passed
- CI Main Process success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34043057118
- CI e2e success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34043057152
- Five-axis review: all `none.`
- `openspec validate` / spec-map / artifact-names OK before archive

### Rank-up moves
None.
