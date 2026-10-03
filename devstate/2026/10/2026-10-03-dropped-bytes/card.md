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
Reviewed head: d0da1907
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Not ready |
| CI proof | 1/6 | not seen |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | N/A | no OPEN PR |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-10-03-dropped-bytes pushed | `git` |
| OpenSpec | none | `openspec/` |
| Pull request | none | pr-host |
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
Ticket 2026-10-03-dropped-bytes on branch 2026-10-03-dropped-bytes targeting master; PR no PR yet; CI not seen.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Which labels does the new `dropped` / `byte` item send? | additive incidental — labels on an item this change creates; no In-scope or criterion line names those labels (Unknowns) | assumed — `origin` + `ip_type` only, same values as the paired request item; omit `remediation` (firewall `dropped` / `byte` shape in `ext_crowdsec_lapi_usage-metrics`) | explore |


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
| Reviewed head | d0da1907b4d2408e5b5738667f4cfc47c0fd0f01 | Card must match the branch you measured |

### Stored data model
None.
