Developer review: in progress — 2026-09-06T15:05:53Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None yet — prepare grounded upstream #377 stream poll freeze in `pkg/lapi` (overlapping polls, lease short-circuit, missing gap tests); implement not started.

**End users.** None.

## Motivation
On `master`, stream mode can silently stop polling `GET /v1/decisions/stream` for ~20 minutes while metrics keeps posting. New bans are not propagated to the Traefik bouncer cache during the gap. Overlapping `handleStreamTicker` goroutines and lease hits that return success without waiting for in-flight polls match the reported duplicate log at resumption and violate the one-poller-per-session spec.

## Merge readiness
Prepare complete; explore is next. 7 workflow items remain.

Priority: P2 — real operator pain (stale ban cache during freeze) with limited blast radius (Traefik keeps serving; LAPI reachable).
Reviewed head: fb48a7e
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Stub PR only; no product change or CI yet |
| CI proof | 1/6 | Pushed; CI not seen |
| Local tests proof | N/A | Before implement |
| Review resolution | N/A | No PR comments inventoried |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-upstream-377-stream-poll-freeze pushed | git push |
| OpenSpec | none | openspec/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/42 | GitHub MCP Create |
| CI | not seen | pr-host CI |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md absent |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local upstream #377 assessment → branch `2026-09-06-upstream-377-stream-poll-freeze` → stub PR #42 → explore next for single-flight vs skip-if-busy and ~20 min root cause.

## Decision needed
None.

## Before merge
- [ ] [P2] Explore stream poll serialization and timeout bounds in `pkg/lapi`
- [ ] [P2] Implement fix and tests for sustained poll gaps
- [ ] [P2] Propose OpenSpec change and land spec updates
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
| Reviewed head | fb48a7e | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Not evaluated yet — prepare only grounded the stall against `DestBranch`.

Do we have a high-confidence way to reproduce? No — upstream report only; no in-repo repro test yet.

Is this the best way to solve the issue? Not evaluated yet — explore will choose single-flight vs skip-if-busy.

### Evidence
What I checked:
- Upstream #377 dump and assessment (`devstate/bug-hunt/2026-09-06/upstream-issues/377*.md`, fb48a7e)
- Stream poll path in `pkg/lapi/client_stream.go`, `client.go`, `client_http.go` (8186c16 on master)

### Rank-up moves
None.
