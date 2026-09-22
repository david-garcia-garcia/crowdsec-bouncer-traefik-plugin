## Motivation
Not yet.

## Implementation
Not yet.

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None.

**End users.** None.

## Merge readiness
In progress. 0 items remain.

Priority: unknown — motivation not written
Reviewed head: 41e6929b
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Not ready |
| CI proof | 1/6 | not seen |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-22-bouncer-instance-severance pushed | `git` |
| OpenSpec | bouncer-instance-severance | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/136 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
None.

## Deviations from the ask
None.

## Follow-up issues
None.

## How this fits together
Ticket 2026-09-22-bouncer-instance-severance on branch 2026-09-22-bouncer-instance-severance targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/136; CI not seen.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Which package owns the dual LAPI/AppSec slot tables and Publish/Subscribe API? | additive asked — new subsystem in scope (“Named LAPI and AppSec slots”, Late bind); criterion names publish/subscribe | assumed — `pkg/instance` owns both slot tables and Publish/Subscribe/Clear; `plugin.go` orchestrates only; tests colocated under that package. | propose |

## Before merge
None.

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
| Reviewed head | 41e6929b57d308df7641d2eabfe01a1a8c75d037 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Not yet.

Do we have a high-confidence way to reproduce? Not yet.

Is this the best way to solve the issue? Not yet.

### Evidence
What I checked:
- assembled from the run bus (`deliver_card`, 41e6929b57d308df7641d2eabfe01a1a8c75d037)

### Rank-up moves
None.
