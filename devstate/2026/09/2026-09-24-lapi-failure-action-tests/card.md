## Motivation
`bouncerLapiFailureAction` already decides a request when LAPI cannot give a verdict. `passthrough` calls next. `ban` forbids. `captcha` serves the challenge. The stream client starts healthy and the first failed poll marks it unhealthy, so a cache miss then uses that knob.

The request tests never drove that poll. The stream case flipped the healthy flag by hand. `captcha` was asserted for an AppSec HTTP 500, not for a LAPI HTTP 500. A regression that banned on `passthrough` after a real stream 500, or that banned instead of challenging on a live LAPI 500, would stay green.

Priority: P3 — tests only, no current operator or end-user harm

## Implementation
Stream mode is constructed against an httptest LAPI that returns 500. The test waits until that constructor poll has fetched once and the client is unhealthy, then `ServeHTTP` checks `passthrough` and `ban`. Live mode is constructed against a LAPI that returns 500 with `captcha` and a challenge template, then `ServeHTTP` checks the remediation header and the page.

## What this changes
**Operators.** None.
**Admin users.** None.
**Developers.** None.
**End users.** None.

## Merge readiness
In progress. 0 items remain.

Priority: P3 — tests only, no current operator or end-user harm
Reviewed head: 13414df0
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
| Branch | 2026-09-24-lapi-failure-action-tests pushed | `git` |
| OpenSpec | lapi-failure-action-request-tests | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/150 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | passed | handoff.yaml localTests |
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
None.

## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-lapi-failure-action-tests/devstate/2026/09/2026-09-24-lapi-failure-action-tests/codereview_standards.md) — 0 total, 0 pending, 0 completed
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-lapi-failure-action-tests/devstate/2026/09/2026-09-24-lapi-failure-action-tests/codereview_nitpicks.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-lapi-failure-action-tests/devstate/2026/09/2026-09-24-lapi-failure-action-tests/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-lapi-failure-action-tests/devstate/2026/09/2026-09-24-lapi-failure-action-tests/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-lapi-failure-action-tests/devstate/2026/09/2026-09-24-lapi-failure-action-tests/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-lapi-failure-action-tests/devstate/2026/09/2026-09-24-lapi-failure-action-tests/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-lapi-failure-action-tests/devstate/2026/09/2026-09-24-lapi-failure-action-tests/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-lapi-failure-action-tests/devstate/2026/09/2026-09-24-lapi-failure-action-tests/codereview_coverage.md) — 0 total, 0 pending, 0 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 13414df04de98c25cdbe104071b338f1708341fc | Card must match the branch you measured |

### Stored data model
None.
