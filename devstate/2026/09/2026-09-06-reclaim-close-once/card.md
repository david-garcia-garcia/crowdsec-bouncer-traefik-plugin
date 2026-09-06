Developer review: in progress — 2026-09-06T14:58:59Z

IssueKey: 2026-09-06-reclaim-close-once
JobName: 2026-09-06-reclaim-close-once

[sgsi-dev-ticket-status:2026-09-06-reclaim-close-once]

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None yet — prepare grounded a reclaim table double-Close bug; product fix not started.

**End users.** None.

## Motivation
On `master`, the reclaim table grace-dispose path can invoke a slot `closeFn` twice (from `fire` and the `life` watcher), breaking the documented exactly-once Close contract. LAPI/AppSec closers tolerate repeats today, but a non-idempotent closer could leak or panic; tests only assert `closes >= 1`.

## Merge readiness
Prepare complete; explore is next. 7 workflow items remain.

Priority: P2 — real internal correctness gap with a workaround (idempotent closers) and limited blast radius today.
Reviewed head: 482e83f
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | CI not measured; no product fix yet |
| CI proof | 1/6 | Pushed; checks not seen |
| Local tests proof | N/A | Before implement |
| Review resolution | N/A | No PR comments inventoried |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-reclaim-close-once pushed | origin |
| OpenSpec | none | handoff.yaml |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/36 | GitHub |
| CI | not seen | no measured checks |
| Local tests | none | handoff.yaml |
| PR comments | no comments | comments: none |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local bug-hunt finding → branch `2026-09-06-reclaim-close-once` → stub PR #36 → CI pending → explore next.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Which single owner should call `closeFn` (`fire` vs `life` watcher) without breaking `ResetForTest` and race-loser paths? | assumed — explore will compare teardown paths and pick one owner | prepare |

## Before merge
- [ ] Explore open questions on dispose ownership
- [ ] Propose OpenSpec change
- [ ] Implement exactly-once Close + strict test
- [ ] Code review five axes
- [ ] Devdocs impact
- [ ] Archive change
- [ ] Pull request final card + green CI
- [x] Prepare: requirement, qualify, stub PR

## Findings
None.

## Axis review
None.

## Agent review details

### Stored data model
None.
