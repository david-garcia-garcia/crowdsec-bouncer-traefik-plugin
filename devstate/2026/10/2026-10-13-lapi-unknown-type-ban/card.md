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
Ready for review. 0 items remain.

Priority: unknown — motivation not written
Reviewed head: 49d30238
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Ready |
| CI proof | 6/6 | succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/38444677056 |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-10-13-lapi-unknown-type-ban pushed | `git` |
| OpenSpec | ban-unknown-lapi-decision-types | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/193 | pr-host |
| CI | build 38444677056 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/38444677056 | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/38444677056 |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
None.

## Deviations from the ask
None.

## Follow-up issues
None.

## How this fits together
Ticket 2026-10-13-lapi-unknown-type-ban on branch 2026-10-13-lapi-unknown-type-ban targeting main; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/193; CI build 38444677056 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/38444677056.

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
| Reviewed head | 49d30238601d24a1cb19b0a4a81c3406b5d5d212 | Card must match the branch you measured |

### Stored data model
None.
