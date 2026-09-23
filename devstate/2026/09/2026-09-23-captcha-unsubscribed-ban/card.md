## Motivation
A bouncing router that never subscribed to captcha (bounce on, empty `CaptchaInstanceName`) can still receive captcha kind: LAPI remediates captcha, a forced decision header `c`, or a captcha failure-action that already reached remediation. That request already becomes a ban. Subscribe is constructor-only: only bounce plus a non-empty instance name watches captcha; bounce-only construction never builds a local client.

When captcha kind arrives on an unsubscribed router, the remediating handler already degrades to ban because the loaded client is nil. It does not tell the operator that this router never subscribed. The 403 looks like a normal CrowdSec ban or a subscribed-unpublished degrade. Startup-block already warns `crowdsec bouncer backend missing` only when the router did subscribe and the client is still nil.

Left alone, operators cannot tell a wiring miss from a real ban. They keep a bouncing router without a captcha instance and treat captcha remediations as ordinary bans, with no log that a challenge could not be served because the router never subscribed.

Priority: P2 — real operator pain, with a workaround or limited blast radius

## Implementation
The remediating handler now checks captcha kind and `subscribeCaptcha` first. When the router never subscribed, it emits WARN `crowdsec bouncer captcha unsubscribed` with `leg=captcha` and `instanceName` (empty when unsubscribed), then the existing ban. The WARN fires on every remediating request that hits that branch: LAPI captcha kind, forced header `c`, and captcha failure-action that already reached this owner. It does not emit `ip`. Subscribed-unpublished and invalid clients stay on the dest ban path with no this WARN. Startup-block subscribed-nil stays 503 plus `crowdsec bouncer backend missing`. No new public config keys. Failure-action `captcha` without an instance name stays illegal at validate.

## What this changes
**Operators.** Every remediating captcha-kind request on an unsubscribed bouncing router now logs WARN `crowdsec bouncer captcha unsubscribed` (`leg=captcha`, empty `instanceName`); the response stays a 403 ban.
**Admin users.** None.
**Developers.** Unsubscribed captcha kind must WARN then ban; this stem must not fire when subscribed, including unpublished or invalid client, and must not carry `ip`.
**End users.** None.

## Merge readiness
In progress. 1 items remain.

Priority: P2 — real operator pain, with a workaround or limited blast radius
Reviewed head: 3f006d73
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
| Branch | 2026-09-23-captcha-unsubscribed-ban pushed | `git` |
| OpenSpec | unsubscribed-captcha-ban-warn | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/139 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-captcha-unsubscribed-ban/openspec/changes/unsubscribed-captcha-ban-warn/proposal.md) — modified


## Deviations from the ask
None.

## Follow-up issues
- [ ] [Rename `handleRemediationServeHTTP`](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-captcha-unsubscribed-ban/knowledge/debt/2026-09-23-rename-handle-remediation-serve-http.md) — `handleRemediationServeHTTP` hides that it owns captcha-kind serve vs ban.


## How this fits together
Ticket 2026-09-23-captcha-unsubscribed-ban on branch 2026-09-23-captcha-unsubscribed-ban targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/139; CI not seen.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Exact WARN message text? | additive asked — new log line this change creates; Unknowns Exact WARN message text | assumed — stem crowdsec bouncer captcha unsubscribed; attrs leg=captcha and instanceName (empty when unsubscribed); traefikName already on the logger from bouncer.New | explore |


## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-captcha-unsubscribed-ban/devstate/2026/09/2026-09-23-captcha-unsubscribed-ban/codereview_standards.md) — 1 total, 0 pending, 1 completed
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-captcha-unsubscribed-ban/devstate/2026/09/2026-09-23-captcha-unsubscribed-ban/codereview_nitpicks.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-captcha-unsubscribed-ban/devstate/2026/09/2026-09-23-captcha-unsubscribed-ban/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-captcha-unsubscribed-ban/devstate/2026/09/2026-09-23-captcha-unsubscribed-ban/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-captcha-unsubscribed-ban/devstate/2026/09/2026-09-23-captcha-unsubscribed-ban/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-captcha-unsubscribed-ban/devstate/2026/09/2026-09-23-captcha-unsubscribed-ban/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-captcha-unsubscribed-ban/devstate/2026/09/2026-09-23-captcha-unsubscribed-ban/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-captcha-unsubscribed-ban/devstate/2026/09/2026-09-23-captcha-unsubscribed-ban/codereview_coverage.md) — 0 total, 0 pending, 0 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 1 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 3f006d73f94e99e4bd4a4f6d6f23eea7a7723410 | Card must match the branch you measured |

### Stored data model
None.
