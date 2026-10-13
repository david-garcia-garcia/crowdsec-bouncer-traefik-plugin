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
Reviewed head: 69337943
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
| Branch | 2026-10-13-count-challenge-once pushed | `git` |
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/197 | pr-host |
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
Ticket 2026-10-13-count-challenge-once on branch 2026-10-13-count-challenge-once targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/197; CI not seen.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Which request path field implements "under `/crowdsec-internal/challenge/`"? | additive asked — Desired names the path prefix; httprule already matches `URL.Path` (1 family in `pkg/httprule`, enumerated with `pkg/bouncer/bouncer.go`) | assumed — use `req.URL.Path` (`strings.HasPrefix(..., "/crowdsec-internal/challenge/")`). Traefik ServeHTTP fills `URL.Path`; do not parse `RequestURI`. | explore |


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
| Reviewed head | 693379435d073748d515530a979e013ba15a5562 | Card must match the branch you measured |

### Stored data model
None.
