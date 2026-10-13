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
Reviewed head: 2b7fae43
Owner decision: None.

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
| Branch | 2026-10-13-challenge-path-terminate pushed | `git` |
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/192 | pr-host |
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
Ticket 2026-10-13-challenge-path-terminate on branch 2026-10-13-challenge-path-terminate targeting main; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/192; CI not seen.

## Explore Decisions
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
| Reviewed head | 2b7fae439d731929b6d2d7d75bd044408f92ac5d | Card must match the branch you measured |

### Stored data model
None.

## Upstream
This fork's gap versus [upstream PR 403](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403) (fixes [issue 402](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/402) point 4): on AppSec allow (or a nil decision) this plugin still calls `next` for `/crowdsec-internal/challenge/*`, so a host-wide middleware leaks those paths to origin. This change terminates that prefix with 404 here; it is not a copy of their patch.
