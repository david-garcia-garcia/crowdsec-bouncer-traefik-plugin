## Motivation
`bouncerRemediationHeadersCustomName` is an optional response header so Traefik JSON access logs (`downstream_<Name>`) can tell a plugin bounce from an origin 403. Drop origin is already known internally for usage-metrics (`MetricsOrigin`, `OriginPlugin*`). The header stays off when the name is empty.

When the name is set, the value is only a kind token: `ban`, `captcha`, `solved-captcha`, `error:client-disconnected`, or a raw AppSec `action`. Every ban page writes `ban` whether the cause was a CrowdSec decision, fail-closed LAPI or cache, AppSec `action: ban`, an empty-body AppSec challenge that fell through to the ban page, an unparseable client IP, or a captcha kind on a router that cannot serve a challenge. Challenge pages write `captcha`; a successful solve writes `solved-captcha`; AppSec envelope relay copies the action as-is. LAPI origin (`crowdsec`, `lists:firehol_level1`, empty intern overflow) never appears on the header.

Operators who panel on those Traefik fields cannot tell a CrowdSec decision from fail-closed or AppSec, and cannot split list vs crowdsec origin without leaving the access log. The only access-log signal stays “plugin handled it,” not why.

Priority: P2 — real operator pain, with a workaround or limited blast radius

## Implementation
An unexported formatter in `pkg/bouncer` joins `kind:reason`, or `kind:reason:origin` when reason is `lapi` and origin is non-empty. Ban, AppSec, disconnect, and captcha-downgrade writers pass an explicit closed reason token; plugin origins stay a reason, never a third field. LAPI third field is header-safe `MetricsOrigin` (strip CR/LF/TAB; prefix `lists:` becomes `lists_` only). Captcha stays a setter: `ServeHTTP` takes the already-formatted challenge value plus the header name; Pass 302 and `WriteSolvedRedirect` write `captcha:solved`. Unknown AppSec actions become `{sanitized-action}:appsec`. Same config key; empty still disables.

## What this changes
**Operators.** When `bouncerRemediationHeadersCustomName` is set, Traefik `downstream_<Name>` values become `kind:reason` or `kind:reason:origin`, so queries matching `ban`, `captcha`, `solved-captcha`, or a raw AppSec action must change (`error:client-disconnected` unchanged; no new key; empty still disables).
**Admin users.** None.
**Developers.** `captcha.Client.ServeHTTP` takes a fifth argument (already-formatted challenge-page header value); header consumers split at most three `:` fields on the closed vocabulary.
**End users.** None.

## Merge readiness
In progress. 0 items remain.

Priority: P2 — real operator pain, with a workaround or limited blast radius
Reviewed head: 7429b33b
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
| Branch | 2026-09-26-remediation-header-reasons pushed | `git` |
| OpenSpec | remediation-header-reasons | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/166 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_appsec_bot-detection](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-26-remediation-header-reasons/openspec/changes/archive/2026-09-26-remediation-header-reasons/proposal.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-26-remediation-header-reasons/openspec/changes/archive/2026-09-26-remediation-header-reasons/proposal.md) — modified
- [core_plugin_middleware_captcha-routing](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-26-remediation-header-reasons/openspec/changes/archive/2026-09-26-remediation-header-reasons/proposal.md) — modified
- [core_plugin_middleware_captcha-widget](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-26-remediation-header-reasons/openspec/changes/archive/2026-09-26-remediation-header-reasons/proposal.md) — modified

Completed:
- [core_plugin_appsec_bot-detection](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-26-remediation-header-reasons/openspec/specs/core_plugin_appsec_bot-detection/spec.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-26-remediation-header-reasons/openspec/specs/core_plugin_middleware_bouncer/spec.md) — modified
- [core_plugin_middleware_captcha-routing](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-26-remediation-header-reasons/openspec/specs/core_plugin_middleware_captcha-routing/spec.md) — modified
- [core_plugin_middleware_captcha-widget](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-26-remediation-header-reasons/openspec/specs/core_plugin_middleware_captcha-widget/spec.md) — modified


## Deviations from the ask
- taken: Ground names `pkg/captcha/captcha.go` `writeRemediationHeader(..., "captcha")` on the challenge page, so captcha would have to know `captcha:lapi[:origin]` / `captcha:decision-header` / failure reasons. → `ServeHTTP` takes the already-formatted challenge-page value from the Bouncer; captcha only writes `captcha:solved` on Pass 302 and `WriteSolvedRedirect`. — `pkg/captcha/captcha.go writeRemediationHeader` — honouring captcha-owned origin mapping would add `MetricsOrigin` / `OriginPlugin*` to a Client whose job is widget and verify; the header name was already lifted off Client for that reason (`core_plugin_middleware_bouncer`).. Requester: not asked.


## Follow-up issues
None.

## How this fits together
Ticket 2026-09-26-remediation-header-reasons on branch 2026-09-26-remediation-header-reasons targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/166; CI not seen.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Where should the emit helper live? | additive asked — Unknowns names helper location; Desired requires structured values at the existing writers | assumed — unexported formatRemediationHeader in pkg/bouncer/remediation_header.go; ban, AppSec, and disconnect call it; captcha does not import the table | explore |


## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-26-remediation-header-reasons/devstate/2026/09/2026-09-26-remediation-header-reasons/codereview_standards.md) — 0 total, 0 pending, 0 completed
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-26-remediation-header-reasons/devstate/2026/09/2026-09-26-remediation-header-reasons/codereview_nitpicks.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-26-remediation-header-reasons/devstate/2026/09/2026-09-26-remediation-header-reasons/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-26-remediation-header-reasons/devstate/2026/09/2026-09-26-remediation-header-reasons/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-26-remediation-header-reasons/devstate/2026/09/2026-09-26-remediation-header-reasons/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-26-remediation-header-reasons/devstate/2026/09/2026-09-26-remediation-header-reasons/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-26-remediation-header-reasons/devstate/2026/09/2026-09-26-remediation-header-reasons/codereview_dead.md) — 1 total, 0 pending, 1 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-26-remediation-header-reasons/devstate/2026/09/2026-09-26-remediation-header-reasons/codereview_coverage.md) — 5 total, 0 pending, 5 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 8 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 7429b33b2c75a25da6497de49d223191c24c7b87 | Card must match the branch you measured |

### Stored data model
None.
