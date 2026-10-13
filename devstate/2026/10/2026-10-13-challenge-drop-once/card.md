## Motivation
CrowdSec AppSec bot-detection answers a suspicious page with JSON `action: challenge`, then the browser loads scripts and posts a proof under `/crowdsec-internal/challenge/`. Each of those AppSec answers was counted as a dropped request, so one solved visit looked like four blocks in the LAPI usage-metrics window.

On this fork's `main`, AppSec 403 was not parsed at all, so those answers were operator bans (empty body, still +1 each). Either way the window over-counts the challenge.

Priority: P2 — operators see inflated dropped counts for every solved bot-detection challenge

## Implementation
`appsecQuery` now parses a 403 JSON body. When `action` is `challenge`, `handleAppsecResponseServeHTTP` writes the envelope to the client. `blockedRequests` increments only when the path is not under `/crowdsec-internal/challenge/`. Other 403s still ban. The metrics POST is unchanged.

## What this changes
**Operators.** A bot-detection challenge page counts as one dropped request; scripts and submit under `/crowdsec-internal/challenge/` do not.
**Admin users.** None.
**Developers.** `appsecQuery` returns `(*AppSecResponse, error)`; a 403 with `action: challenge` is a nil error plus the envelope.
**End users.** The browser receives the AppSec challenge HTML instead of the operator ban page when AppSec returns that envelope.

## Merge readiness
In progress. 0 items remain.

Priority: P2 — operators see inflated dropped counts for every solved bot-detection challenge
Reviewed head: 75a7dc55
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
| Branch | 2026-10-13-challenge-drop-once pushed | `git` |
| OpenSpec | count-challenge-drop-once | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/195 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
None.

## Deviations from the ask
- taken: a relay under `/crowdsec-internal/challenge/` does not increment dropped (request or bytes). → skip `blockedRequests` only; do not add a bytes series. — `bouncer.go reportMetrics` — dest's metrics POST has a single `dropped` request item and no bytes series; adding bytes would change the POST shape, which the ask forbids.. Requester: not asked.


## Follow-up issues
None.

## How this fits together
Ticket 2026-10-13-challenge-drop-once on branch 2026-10-13-challenge-drop-once targeting main; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/195; CI not seen.

Upstream: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 (fixes https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/402, point 5). This fork's `main` had no challenge relay (#343 not merged). We added a minimal 403 JSON relay and skip `blockedRequests` on `/crowdsec-internal/challenge/*`. We are not copying their patch.

## Explore Decisions
None.

## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-challenge-drop-once/devstate/2026/10/2026-10-13-challenge-drop-once/codereview_standards.md) — 0 total, 0 pending, 0 completed
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-challenge-drop-once/devstate/2026/10/2026-10-13-challenge-drop-once/codereview_nitpicks.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-challenge-drop-once/devstate/2026/10/2026-10-13-challenge-drop-once/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-challenge-drop-once/devstate/2026/10/2026-10-13-challenge-drop-once/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-challenge-drop-once/devstate/2026/10/2026-10-13-challenge-drop-once/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-challenge-drop-once/devstate/2026/10/2026-10-13-challenge-drop-once/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-challenge-drop-once/devstate/2026/10/2026-10-13-challenge-drop-once/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-challenge-drop-once/devstate/2026/10/2026-10-13-challenge-drop-once/codereview_coverage.md) — 0 total, 0 pending, 0 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 75a7dc55fa85cf8e5244925c8a160380ac239ff9 | Card must match the branch you measured |

### Stored data model
None.
