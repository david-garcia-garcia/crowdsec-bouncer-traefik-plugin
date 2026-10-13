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
Reviewed head: dd05046e
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
| Branch | 2026-10-13-lapi-unknown-type-ban pushed | `git` |
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/193 | pr-host |
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
Ticket 2026-10-13-lapi-unknown-type-ban on branch 2026-10-13-lapi-unknown-type-ban targeting main; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/193; CI not seen.

This fork's take on https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 (fixes https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/402, point 1). Gap versus that PR: dest `main` still stores unknown LAPI types as an empty cache payload, so stream Get treats them as a miss and allows the IP. We did not copy their patch.

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
| Reviewed head | dd05046ec5978bacc9499b68fb16862689d3c3f1 | Card must match the branch you measured |

### Stored data model
None.
