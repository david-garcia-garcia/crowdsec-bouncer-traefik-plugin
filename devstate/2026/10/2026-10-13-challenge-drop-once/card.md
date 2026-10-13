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
Reviewed head: a3460484
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
| Branch | 2026-10-13-challenge-drop-once pushed | `git` |
| OpenSpec | count-challenge-drop-once | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/195 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
None.

## Deviations from the ask
- taken: a relay under `/crowdsec-internal/challenge/` does not increment dropped (request or bytes). → skip `blockedRequests` only; do not add a bytes series. — `bouncer.go reportMetrics` — dest's metrics POST has a single `dropped` request item and no bytes series; adding bytes would change the POST shape, which the ask forbids.. Requester: not asked.


## Follow-up issues
None.

## How this fits together
Ticket 2026-10-13-challenge-drop-once on branch 2026-10-13-challenge-drop-once targeting main; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/195; CI not seen.

Upstream: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 (fixes https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/402, point 5). This fork's `main` has not merged upstream #343, so dest had no challenge relay; PR 403 point 5 skips the dropped increment on `/crowdsec-internal/challenge/*`. We add a minimal relay plus that skip. We are not copying their patch.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Dest has no challenge relay; can the skip attach without adding one? | additive asked — new relay unit this change creates; Desired names a relayed AppSec challenge envelope | assumed — add a minimal challenge-JSON relay in `bouncer.go` and skip `blockedRequests` under `/crowdsec-internal/challenge/`; do not merge #343 wholesale | explore |


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
| Reviewed head | a346048466a84e2897bbb290fef68e1b29a3b614 | Card must match the branch you measured |

### Stored data model
None.
