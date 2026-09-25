## Motivation
When Traefik rebuilds a captcha-owning middleware, captcha Open reclaims by OwnershipKey: middleware name plus instance-owned captcha knobs (provider, keys, files, timeouts, template, gate, custom paths, and the recaptcha-enterprise knobs). Create is the only path that stores the constructor logger on the Client. Reclaim Wakes that Client; bindIdentity does not replace the logger.

A rebuild that changes only log config still hashes the same Open key. The operator example is `logLevel` from `trace` to `debug`; `logFilePath` and `logFormat` are omitted the same way. Those three knobs already freeze into one logger at middleware New, then Open reclaims the prior Client, so captcha keeps the old TRACE logger (or the old file and format).

Left alone, a log-config-only rebuild does not change captcha logging. TRACE stays noisy after the operator turned it down; DEBUG never appears after they turned it up. The same stale logger remains until some other ownership knob changes or the process disposes that incarnation.

Priority: P2 — real operator pain, with a workaround or limited blast radius

## Implementation
The captcha ownership payload now hashes `LogLevel`, `LogFilePath`, and `LogFormat` as stored on Config, so OwnershipKey forks when any of those knobs change. A log-config-only rebuild therefore misses the old key; Open creates and the constructor stores the rebuilt logger. Reclaim, bindIdentity, and logger construction stay as they were. The previous incarnation follows the existing table path: Sleep, grace, Close; the captcha instance alias remaps to the new Client. Coverage is key-inequality for each of the three knobs. The instance-slots ownership Open-key SHALL now includes `logLevel`, `logFilePath`, and `logFormat`.

## What this changes
**Operators.** Changing `logLevel`, `logFilePath`, or `logFormat` on a captcha owner now starts a new captcha client instead of waking the previous one.
**Admin users.** None.
**Developers.** Captcha `OwnershipKey` now includes those three log knobs, so a log-config-only rebuild is a different Open key, and the instance-slots SHALL lists them.
**End users.** None.

## Merge readiness
Ready for review. 0 items remain.

Priority: P2 — real operator pain, with a workaround or limited blast radius
Reviewed head: 65053ac3
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Ready |
| CI proof | 6/6 | succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/36134927230 |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-25-log-config-reclaim-key pushed | `git` |
| OpenSpec | include-log-config-in-captcha-reclaim-key | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/162 | pr-host |
| CI | build 36134927230 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/36134927230 | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/36134927230 |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_middleware_instance-slots](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-log-config-reclaim-key/openspec/changes/include-log-config-in-captcha-reclaim-key/proposal.md) — modified


## Deviations from the ask
None.

## Follow-up issues
None.

## How this fits together
Ticket 2026-09-25-log-config-reclaim-key on branch 2026-09-25-log-config-reclaim-key targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/162; CI build 36134927230 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/36134927230.

## Explore Decisions
None.

## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-log-config-reclaim-key/devstate/2026/09/2026-09-25-log-config-reclaim-key/codereview_standards.md) — 1 total, 0 pending, 1 completed
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-log-config-reclaim-key/devstate/2026/09/2026-09-25-log-config-reclaim-key/codereview_nitpicks.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-log-config-reclaim-key/devstate/2026/09/2026-09-25-log-config-reclaim-key/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-log-config-reclaim-key/devstate/2026/09/2026-09-25-log-config-reclaim-key/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-log-config-reclaim-key/devstate/2026/09/2026-09-25-log-config-reclaim-key/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-log-config-reclaim-key/devstate/2026/09/2026-09-25-log-config-reclaim-key/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-log-config-reclaim-key/devstate/2026/09/2026-09-25-log-config-reclaim-key/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-log-config-reclaim-key/devstate/2026/09/2026-09-25-log-config-reclaim-key/codereview_coverage.md) — 0 total, 0 pending, 0 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 1 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 65053ac37f03b78514147e35f96acefd953dccfd | Card must match the branch you measured |

### Stored data model
None.
