Developer review: in progress — 2026-09-06T15:29:55Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** Unit tests in `pkg/appsec/query_test.go` and `pkg/bouncer/bouncer_test.go` prove AppSec JSON `action: captcha` parse and relay (including the no-body 403 envelope). OpenSpec change `appsec-captcha-action-tests` adds those scenarios on `core_plugin_appsec_bot-detection`.

**End users.** None.

## Motivation
On `master`, AppSec JSON `action: captcha` is parsed and relayed but no test or spec scenario named that envelope. Upstream #357 reports missing captcha support; without these tests, a regression can restore that gap without CI catching it.

## Merge readiness
Implement complete; code review is next. 4 workflow items remain.

Priority: P3 — tests and spec clarity; no current operator or end-user harm if behavior is already correct.
Reviewed head: 5c63441
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Local tests passed; CI succeeded; no open PR comments |
| CI proof | 6/6 | Succeeded — [Main Process](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041799482), [e2e](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041799456) |
| Local tests proof | N/A | Remote PR; CI covers |
| Review resolution | 6/6 | No PR comments inventoried |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-upstream-357-appsec-captcha-action pushed | git push |
| OpenSpec | appsec-captcha-action-tests | openspec/changes/appsec-captcha-action-tests/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/44 | pr-host |
| CI | build 34041799482 success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041799482 ; build 34041799456 success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041799456 | GitHub check runs |
| Local tests | passed | `go test ./pkg/appsec/ ./pkg/bouncer/ -count=1` |
| PR comments | no comments | comments.md absent |

## Specs
- [core_plugin_appsec_bot-detection](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-357-appsec-captcha-action/openspec/changes/appsec-captcha-action-tests/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
Local upstream #357 assessment → branch `2026-09-06-upstream-357-appsec-captcha-action` → stub PR #44 → tests landed → CI green → code review next.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Should empty-body AppSec `action: captcha` ban like empty `challenge`, or relay status with no body? | assumed — keep current relay (`handleAppsecResponseServeHTTP`); tests assert `http_status` (403 in the upstream example) and empty body, not the operator ban page. | explore |
| Fold captcha scenarios onto `core_plugin_appsec_bot-detection` or create a new spec? | assumed — MODIFIED on `core_plugin_appsec_bot-detection` (add parse + relay scenarios for `action: captcha`, including the no-body envelope). No new leaf. | explore |

## Before merge
- [ ] [P3] Five-axis code review, archive OpenSpec change, drop WIP on PR #44
- [x] Add captcha JSON parse and bouncer relay tests (including empty-body envelope)
- [x] Propose OpenSpec change `appsec-captcha-action-tests` on `core_plugin_appsec_bot-detection`
- [x] Explore: empty-body captcha stays relay; lock envelope parse+relay not `pkg/captcha`
- [x] Prepare: requirement, worktree, stub PR

## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 1 modified | Same list as Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | No comments on stub PR |
| Reviewed head | 5c63441ecea690c41b3537159b848a3000b30af8 | Matches pushed implement commit |

### Stored data model
None.

### Technical review
Best possible solution: tests lock current envelope parse and relay next to the existing challenge fixtures, without changing product code.

Do we have a high-confidence way to reproduce? Yes — `Test_appsecQuery_captchaJSON`, `TestHandleNextServeHTTPRelaysStructuredAppsecCaptcha`, `TestHandleNextServeHTTPEmptyCaptchaBodyRelaysStatus` passed locally and in CI.

Is this the best way to solve the issue? Yes for add-tests scope — product already parses and relays captcha HTML, distinct from `pkg/captcha`.

### Evidence
What I checked:
- `go test ./pkg/appsec/ ./pkg/bouncer/ -count=1` passed
- CI Main Process success (run 34041799482); e2e success (run 34041799456)
- Product delta vs `origin/master`: tests + OpenSpec change only (HEAD 5c63441)

### Rank-up moves
None.
