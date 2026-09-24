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
Reviewed head: 84820b4d
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
| Branch | 2026-09-24-lapi-failure-action-tests pushed | `git` |
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/150 | pr-host |
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
Ticket 2026-09-24-lapi-failure-action-tests on branch 2026-09-24-lapi-failure-action-tests targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/150; CI not seen.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Must the stream assertion wait on the constructor's poll, or may it drive one poll by hand? | additive asked — a new test; existing callers stay; Desired names a real failed stream GET | assumed — `New` against a 500 stream, wait until `StreamHealthy` is false, then `ServeHTTP` for `passthrough` and `ban`. | explore |


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
| Reviewed head | 84820b4d3f2672d0ab3eb8494fa6f33287e01b91 | Card must match the branch you measured |

### Stored data model
None.
