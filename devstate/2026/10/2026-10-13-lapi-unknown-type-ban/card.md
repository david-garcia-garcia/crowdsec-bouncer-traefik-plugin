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
Reviewed head: 604ad777
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

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Should unknown LAPI types be stored as `cache.BannedValue` at both ingest switches, including live which already remediates an empty return as a ban? | bounded asked — 2 existing switches in `bouncer.go` (roots searched: `bouncer.go`); Desired: stored and applied as a ban in stream and live | assumed — yes; set `cache.BannedValue` in both `default` branches so stream Get and live cache hits stay bans. | explore |


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
| Reviewed head | 604ad777164202daf41d2dc5b07238c1be154ebc | Card must match the branch you measured |

### Stored data model
None.
