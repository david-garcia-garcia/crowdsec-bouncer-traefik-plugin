Developer review: in progress — 2026-09-06T15:17:14Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** OpenSpec change `serialize-stream-poll` folds one in-flight stream poll (TryLock skip is not success) into `core_plugin_middleware_instance-reclaim` and an `HTTPTimeoutSeconds` request deadline into `core_plugin_lapi_connection`. No runtime code versus `master` yet.

**End users.** None.

## Motivation
On `master`, stream mode can silently stop polling `GET /v1/decisions/stream` for ~20 minutes while metrics keeps posting. New bans are not propagated to the Traefik bouncer cache during the gap. Overlapping ticker/`Wake` goroutines treat a lease hit as a successful poll and can race CrowdSec’s stream cursor.

## Merge readiness
Propose complete; implement is next. 5 workflow items remain.

Priority: P2 — real operator pain (stale ban cache during freeze) with limited blast radius (Traefik keeps serving; LAPI reachable).
Reviewed head: 9f921e3
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Proposal landed; no runtime change or green CI |
| CI proof | 3/6 | Checks queued on 9f921e3 |
| Local tests proof | N/A | Before implement |
| Review resolution | N/A | No PR comments inventoried |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-upstream-377-stream-poll-freeze pushed | git push |
| OpenSpec | serialize-stream-poll | openspec/changes/serialize-stream-poll/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/42 | GitHub MCP |
| CI | build 34041821394 queued https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041821394 | pull_request_read get_check_runs |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | comments.md absent |

## Specs
- [core_plugin_middleware_instance-reclaim](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-377-stream-poll-freeze/openspec/changes/serialize-stream-poll/proposal.md) — modified
- [core_plugin_lapi_connection](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-377-stream-poll-freeze/openspec/changes/serialize-stream-poll/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
Local upstream #377 → branch `2026-09-06-upstream-377-stream-poll-freeze` → stub PR #42 → explore TryLock skip → propose `serialize-stream-poll` → implement next.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| What maps to the reporter’s exact ~20 minute gap with no `handleStreamCache:updated` lines? | assumed — native Go already bounds `crowdsecQuery` with `http.Client.Timeout`. The gap matches a ticker blocked on work (upstream sync ticker, or Yaegi not firing the timer) plus a transport stall, not a product constant. Do not bake 20 minutes. Keep `go work()`, TryLock skip, and a request context deadline. | explore |
| TryLock skip or mutex-wait single-flight? | assumed — TryLock skip. Waiting would queue `go work()` goroutines behind a hung poll. Skip must not count as success. Redis lease-hit after owning the slot still counts as success. | explore |
| Add `context.WithTimeout` when `http.Client.Timeout` already works in native Go? | assumed — yes. One request deadline from `HTTPTimeoutSeconds`. Cheap, testable, and covers Do paths that might otherwise hang after headers. Do not add Yaegi-specific workarounds. | explore |

## Before merge
- [ ] [P2] Implement TryLock skip, request timeout, and tests
- [x] Propose OpenSpec `serialize-stream-poll`
- [x] Explore: overlapping lease-as-success reproduced; 20-minute freeze not reproduced in native Go
- [x] Prepare: requirement, worktree, stub PR

## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 2 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 9f921e347d0f2c3a153eabe772f1113760c7c19b | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: TryLock skip plus a request deadline, leaving async ticker work — versus `master`, where overlapping polls treat a lease hit as success.

Do we have a high-confidence way to reproduce? Yes for in-process overlap (throwaway tests during explore). No for the exact 20-minute freeze in native Go.

Is this the best way to solve the issue? Yes versus `master` — serialize without blocking the ticker.

### Evidence
What I checked:
- `openspec/changes/serialize-stream-poll/` proposal, design, tasks, two spec deltas (9f921e3)
- `openspec validate serialize-stream-poll --type change --strict` passed

### Rank-up moves
None.
