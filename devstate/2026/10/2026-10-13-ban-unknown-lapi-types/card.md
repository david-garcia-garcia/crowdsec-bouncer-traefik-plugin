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
Reviewed head: 0a83d26e
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
| Branch | 2026-10-13-ban-unknown-lapi-types pushed | `git` |
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/198 | pr-host |
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
Ticket 2026-10-13-ban-unknown-lapi-types on branch 2026-10-13-ban-unknown-lapi-types targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/198; CI not seen.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Should stream Range upserts map unknown types to ban, not only streamPutItem? | bounded asked — 1 Range call site in pkg/lapi/client_stream.go plus 3 other ingest sites in pkg/lapi (roots: pkg/); Desired names stream store and apply | assumed — include Range in the ingest helper; still not RemediationValue. | explore |


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
| Reviewed head | 0a83d26eae1c3fc6f8b5b1605a488c654dd6a4c1 | Card must match the branch you measured |

### Stored data model
None.
