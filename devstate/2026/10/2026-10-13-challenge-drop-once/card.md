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
Reviewed head: ae44ed02
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Limited confidence |
| CI proof | 3/6 | in progress |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-10-13-challenge-drop-once pushed | `git` |
| OpenSpec | count-challenge-drop-once | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/195 | pr-host |
| CI | build 38441923125 in progress | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/38441923125 |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
None.

## Deviations from the ask
- taken: a relay under `/crowdsec-internal/challenge/` does not increment dropped (request or bytes). → skip `blockedRequests` only; do not add a bytes series. — `bouncer.go reportMetrics` — dest's metrics POST has a single `dropped` request item and no bytes series; adding bytes would change the POST shape, which the ask forbids.. Requester: not asked.


## Follow-up issues
None.

## How this fits together
Ticket 2026-10-13-challenge-drop-once on branch 2026-10-13-challenge-drop-once targeting main; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/195; CI build 38441923125 in progress.

Upstream: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 (fixes https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/402, point 5). This fork's `main` had no challenge relay (#343 not merged). We added a minimal 403 JSON relay and skip `blockedRequests` on `/crowdsec-internal/challenge/*`. We are not copying their patch.

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
| Reviewed head | ae44ed020d427b5f8e69733c3c7bad6ca45ab40d | Card must match the branch you measured |

### Stored data model
None.
