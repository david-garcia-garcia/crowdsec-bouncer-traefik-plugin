Developer review: ready for review — 2026-09-06T15:53:52Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** Unit tests in `pkg/appsec/query_test.go` and `pkg/bouncer/bouncer_test.go` prove AppSec JSON `action: captcha` parse and relay, including the no-body `{"action":"captcha","http_status":403}` envelope. Spec `core_plugin_appsec_bot-detection` names those scenarios. Usage packet `core_plugin_appsec.md` says empty captcha body still relays `http_status`.

**End users.** None.

## Motivation
On `master`, AppSec JSON `action: captcha` is parsed and relayed but no test or spec scenario named that envelope. Upstream #357 reports missing captcha support; without these tests, a regression can restore that gap without CI catching it.

## Merge readiness
Ready for review. 0 items remain.

Priority: P3 — tests and spec clarity; no current operator or end-user harm if behavior is already correct.
Reviewed head: f417f68
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | CI succeeded; no open PR comments; local tests passed |
| CI proof | 6/6 | Succeeded — [Main Process](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34043520887), [e2e](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34043520884) |
| Local tests proof | N/A | Remote PR; CI covers |
| Review resolution | 6/6 | No PR comments inventoried |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-upstream-357-appsec-captcha-action pushed | git push |
| OpenSpec | appsec-captcha-action-tests (archived) | openspec/changes/archive/2026-09-06-appsec-captcha-action-tests/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/44 | pr-host |
| CI | build 34043520887 success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34043520887 ; build 34043520884 success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34043520884 | GitHub check runs |
| Local tests | passed | `go test ./pkg/appsec/ ./pkg/bouncer/ -count=1` |
| PR comments | no comments | comments.md absent |

## Specs
- [core_plugin_appsec_bot-detection](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-357-appsec-captcha-action/openspec/changes/archive/2026-09-06-appsec-captcha-action-tests/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
Local upstream #357 assessment → branch `2026-09-06-upstream-357-appsec-captcha-action` → PR #44 → tests + spec scenarios + usage How-to → CI green.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Should empty-body AppSec `action: captcha` ban like empty `challenge`, or relay status with no body? | assumed — keep current relay (`handleAppsecResponseServeHTTP`); tests assert `http_status` (403 in the upstream example) and empty body, not the operator ban page. | explore |
| Fold captcha scenarios onto `core_plugin_appsec_bot-detection` or create a new spec? | assumed — MODIFIED on `core_plugin_appsec_bot-detection` (add parse + relay scenarios for `action: captcha`, including the no-body envelope). No new leaf. | explore |

## Before merge
None.

## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-357-appsec-captcha-action/devstate/2026/09/2026-09-06-upstream-357-appsec-captcha-action/codereview_standards.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-357-appsec-captcha-action/devstate/2026/09/2026-09-06-upstream-357-appsec-captcha-action/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-357-appsec-captcha-action/devstate/2026/09/2026-09-06-upstream-357-appsec-captcha-action/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-357-appsec-captcha-action/devstate/2026/09/2026-09-06-upstream-357-appsec-captcha-action/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-357-appsec-captcha-action/devstate/2026/09/2026-09-06-upstream-357-appsec-captcha-action/codereview_dead.md) — 0 total, 0 pending, 0 completed

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 1 modified | Same list as Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | No comments on stub PR |
| Reviewed head | f417f683ecfb0044d7deb6fbee48a10b89e7cc53 | Matches pushed head with green CI |

### Stored data model
None.

### Technical review
Best possible solution: tests lock current envelope parse and relay next to the existing challenge fixtures, without changing product behavior.

Do we have a high-confidence way to reproduce? Yes — `Test_appsecQuery_captchaJSON`, `TestHandleNextServeHTTPRelaysStructuredAppsecCaptcha`, and `TestHandleNextServeHTTPEmptyCaptchaBodyRelaysStatus` passed locally and in CI.

Is this the best way to solve the issue? Yes for add-tests scope — product already parses and relays captcha HTML, distinct from `pkg/captcha`.

### Evidence
What I checked:
- `go test ./pkg/appsec/ ./pkg/bouncer/ -count=1` passed
- CI Main Process success (run 34043520887); e2e success (run 34043520884) after a docker+pester flake (`no test-results.xml`)
- Five-axis review of `origin/master...HEAD` excluding `devstate/` and `.cursor/` — all `none.`

### Rank-up moves
None.
