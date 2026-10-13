[sgsi-dev-ticket-status:2026-09-06-configuration-validateparams]

Developer review: ready for review — 2026-09-06T15:09:11Z

IssueKey: 2026-09-06-configuration-validateparams
JobName: 2026-09-06-configuration-validateparams

## What this changes
**Operators.** Misconfigured AppSec HTTPS, alone-mode captcha/template, or logging settings are rejected at plugin startup instead of failing later at runtime.

**Admin users.** None.

**Developers.** `ValidateParams` in `pkg/configuration` validates AppSec with the effective scheme and AppSec CA PEM, runs captcha/template/log checks in alone mode, and adds unit tests for previously untested branches.

**End users.** None.

## Motivation
On `master`, `ValidateParams` validates AppSec URLs with the LAPI scheme, skips AppSec TLS CA parsing, and alone mode returns before captcha/template/log checks. Broken configs can start Traefik and fail later during AppSec dial or captcha remediation. This PR closes those startup validation gaps.

## Merge readiness
All checks green; ready for review. 0 items remain.

Priority: P2 — real operator pain from late runtime failures, with a workaround (fix config after crash/log errors).

Reviewed head: 0b68942
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | CI succeeded, local configuration tests passed |
| CI proof | 6/6 | Main Process, e2e binary, e2e docker all success |
| Local tests proof | 6/6 | `go test ./pkg/configuration/...` passed |
| Review resolution | 6/6 | No open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-configuration-validateparams pushed | git push |
| OpenSpec | configuration-validateparams (archived) | openspec/changes/archive/2026-09-06-configuration-validateparams/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/32 | pr #32 |
| CI | Main Process success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041196550/job/101508146203 | GitHub check runs |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | comments: none |

## Specs
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-configuration-validateparams/openspec/changes/archive/2026-09-06-configuration-validateparams/proposal.md) — added

## Follow-up issues
None.

## How this fits together
Local bug-hunt ticket → branch `2026-09-06-configuration-validateparams` → PR #32 → CI green on head `0b68942`.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Whether AppSec client cert fields need startup parse in ValidateParams, or CA-only parity is enough? | assumed — CA-only at ValidateParams matches LAPI; client cert errors surface at `GetTLSConfigCrowdsec` / `appsec.Open` | explore |

## Before merge
None.

## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-configuration-validateparams/devstate/2026/09/2026-09-06-configuration-validateparams/codereview_standards.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-configuration-validateparams/devstate/2026/09/2026-09-06-configuration-validateparams/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-configuration-validateparams/devstate/2026/09/2026-09-06-configuration-validateparams/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-configuration-validateparams/devstate/2026/09/2026-09-06-configuration-validateparams/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-configuration-validateparams/devstate/2026/09/2026-09-06-configuration-validateparams/codereview_dead.md) — 0 total, 0 pending, 0 completed

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 1 added | core_plugin_middleware_config-validation |
| Open reviewer comments walked | 0 | No PR comments |
| Reviewed head | 0b68942ba9a5dd811b0206660105a61a73fe9390 | Matches pushed branch |

### Stored data model
None.

### Technical review
Best possible solution: Yes — minimal refactor in pkg/configuration with spec-backed tests; no captcha runtime changes per ticket boundary.

Do we have a high-confidence way to reproduce? Yes — unit tests cover AppSec scheme/TLS, alone mode, and helper gaps.

Is this the best way to solve the issue? Yes — fail-fast at ValidateParams mirrors runtime TLS/scheme contracts.

### Evidence
What I checked:
- `go test ./pkg/configuration/...` passed locally
- CI Main Process + both e2e jobs success on 0b68942 (GitHub check runs)

### Rank-up moves
None.
