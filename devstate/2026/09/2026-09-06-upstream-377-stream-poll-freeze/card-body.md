Developer review: in progress — 2026-09-06T15:13:03Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None yet versus `master` — explore chose TryLock skip for in-process stream polls (skip is not success), keep `go work()` on the ticker, and bound `crowdsecQuery` with `HTTPTimeoutSeconds`. No product files in `origin/master...HEAD`.

**End users.** None.

## Motivation
On `master`, stream mode can silently stop polling `GET /v1/decisions/stream` for ~20 minutes while metrics keeps posting. New bans are not propagated to the Traefik bouncer cache during the gap. Overlapping `handleStreamTicker` goroutines and lease hits that return success without waiting for in-flight polls match the reported duplicate log at resumption and violate the one-poller-per-session spec.

## Merge readiness
Explore complete; propose is next. 6 workflow items remain.

Priority: P2 — real operator pain (stale ban cache during freeze) with limited blast radius (Traefik keeps serving; LAPI reachable).
Reviewed head: 8a17f18
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Stub PR; explore done; no product change |
| CI proof | 3/6 | Checks queued on 8a17f18 |
| Local tests proof | N/A | Before implement |
| Review resolution | N/A | No PR comments inventoried |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-upstream-377-stream-poll-freeze pushed | git push |
| OpenSpec | none | openspec/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/42 | GitHub MCP |
| CI | build 34041573365 queued https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041573365 | pull_request_read get_check_runs |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | pull_request_read get_comments |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local upstream #377 → branch `2026-09-06-upstream-377-stream-poll-freeze` → stub PR #42 → explore recorded TryLock skip + timeout bound → propose next.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| What maps to the reporter’s exact ~20 minute gap with no `handleStreamCache:updated` lines? | assumed — native Go already bounds `crowdsecQuery` with `http.Client.Timeout`. The gap matches a ticker blocked on work (upstream sync ticker, or Yaegi not firing the timer) plus a transport stall, not a product constant. Do not bake 20 minutes. Keep `go work()`, TryLock skip, and a request context deadline. | explore |
| TryLock skip or mutex-wait single-flight? | assumed — TryLock skip. Waiting would queue `go work()` goroutines behind a hung poll. Skip must not count as success. Redis lease-hit after owning the slot still counts as success. | explore |
| Add `context.WithTimeout` when `http.Client.Timeout` already works in native Go? | assumed — yes. One request deadline from `HTTPTimeoutSeconds`. Cheap, testable, and covers Do paths that might otherwise hang after headers. Do not add Yaegi-specific workarounds. | explore |

## Before merge
- [ ] [P2] Propose OpenSpec change for one in-flight stream poll per Client
- [ ] [P2] Implement TryLock skip, request timeout, and tests
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
| Specs in this PR | none | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 8a17f1812d6e64b14d4e6de2ada2daea9e781f87 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: TryLock skip plus a request deadline on `crowdsecQuery`, leaving `go work()` so the ticker cannot stall — versus `master`, where overlapping ticker/Wake goroutines treat a lease hit as a successful poll.

Do we have a high-confidence way to reproduce? Yes for in-process overlap (throwaway tests: 8 extra tickers returned success on one in-flight GET; concurrent cache-miss issued 2 GETs). No for the exact 20-minute freeze (native Go timeout returned in ~1s).

Is this the best way to solve the issue? Yes versus `master` — serialize without blocking the ticker, and do not count an in-process skip as healthy.

### Evidence
What I checked:
- Throwaway `TestRepro_` in `pkg/lapi` (deleted): lease-mask 1 GET / 8 success returns; concurrent miss 2 GETs / 8 nil returns; `Client.Timeout` 1s bound (8a17f18 worktree, not committed)
- `pkg/lapi/client.go` `startTicker` `go work()`, `Wake` extra poll; `client_stream.go` lease short-circuit (8186c16 on master)
- `knowledge/devdocs/core_plugin_middleware.md`, `std_go_reclaim.md`, `knowledge/research/ext_crowdsec_lapi_stream-cursor/notes.md`

### Rank-up moves
None.
