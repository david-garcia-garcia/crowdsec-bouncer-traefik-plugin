Developer review: in progress — 2026-09-06T15:06:13Z

[sgsi-dev-ticket-status:2026-09-06-upstream-370-stream-poll-lease-interval-one]

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None yet — prepare only; tests for stream poll lease at `updateIntervalSeconds: 1` are scoped on the branch.

**End users.** None.

## Motivation
On `master`, upstream #370 showed that when `updateIntervalSeconds` is 1, a lease TTL of `updateInterval - 1` (= 0) never stores the stream poll guard key, so multi-instance deployments poll LAPI every tick. This fork already floors lease duration at 1 second in `pkg/lapi/client_stream.go`, but no test proves that behavior — a regression could reintroduce the upstream failure silently.

## Merge readiness
Prepare complete; explore and implement remain. 8 workflow items remain.

Priority: P3 — test coverage and internal proof; no current operator or end-user harm on the fork.
Reviewed head: 655f4ea
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | N/A | Prepare only; no product apply yet |
| CI proof | 1/6 | Branch pushed; CI not seen |
| Local tests proof | N/A | Before implement |
| Review resolution | N/A | No PR comments inventoried |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-upstream-370-stream-poll-lease-interval-one pushed | git push |
| OpenSpec | none | openspec/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/47 | pr-host Create |
| CI | not seen | pr-host CI |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local bug-hunt assessment for upstream #370 → branch `2026-09-06-upstream-370-stream-poll-lease-interval-one` → stub PR #47 → CI pending → add-tests to prove lease storage at interval 1.

## Decision needed
None.

## Before merge
- [ ] [P3] Explore and propose OpenSpec change for interval-1 lease tests
- [ ] [P3] Implement tests in `pkg/lapi` proving lease store when `updateIntervalSeconds: 1`
- [x] Prepare: requirement, ticket dump, stub PR

Do not list the eight workflow phases here. Those live on `devstate/progress.md`.

## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | No spec.md delta yet |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 655f4ea | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: not evaluated yet — prepare scoped add-tests only; product fix already on master.

Do we have a high-confidence way to reproduce? No — proof test not written yet.

Is this the best way to solve the issue? Yes — add-tests matches assessment `present-fixed-unproven` without changing behavior.

### Evidence
What I checked:
- `pkg/lapi/client_stream.go:77-81` lease floor at 1 second (8186c16, tree walk)
- `pkg/lapi/client_range_test.go:54-64` lease-hit test uses TTL 60 only (8186c16)
- Ticket assessment `recommended-action: add-tests` (local dump)

### Rank-up moves
None.
