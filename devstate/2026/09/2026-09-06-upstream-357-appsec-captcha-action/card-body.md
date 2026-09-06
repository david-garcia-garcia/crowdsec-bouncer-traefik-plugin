Developer review: in progress — 2026-09-06T15:34:35Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** Unit tests in `pkg/appsec/query_test.go` and `pkg/bouncer/bouncer_test.go` prove AppSec JSON `action: captcha` parse and relay (including the no-body 403 envelope). OpenSpec change `appsec-captcha-action-tests` adds those scenarios on `core_plugin_appsec_bot-detection`. Usage packet `core_plugin_appsec.md` now says empty captcha body still relays `http_status`.

**End users.** None.

## Motivation
On `master`, AppSec JSON `action: captcha` is parsed and relayed but no test or spec scenario named that envelope. Upstream #357 reports missing captcha support; without these tests, a regression can restore that gap without CI catching it.

## Merge readiness
Devdocs impact complete; archive is next. 2 workflow items remain.

Priority: P3 — tests and spec clarity; no current operator or end-user harm if behavior is already correct.
Reviewed head: de3f9b9
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Usage packet updated; latest CI still queued |
| CI proof | 3/6 | In progress — [run 34042747298](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34042747298) |
| Local tests proof | N/A | Remote PR; CI covers |
| Review resolution | 6/6 | No PR comments inventoried |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-upstream-357-appsec-captcha-action pushed | git push |
| OpenSpec | appsec-captcha-action-tests | openspec/changes/appsec-captcha-action-tests/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/44 | pr-host |
| CI | in progress [run 34042747298](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34042747298) | GitHub check runs |
| Local tests | passed | `go test ./pkg/appsec/ ./pkg/bouncer/ -count=1` |
| PR comments | no comments | comments.md absent |

## Specs
- [core_plugin_appsec_bot-detection](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-357-appsec-captcha-action/openspec/changes/appsec-captcha-action-tests/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
Local upstream #357 assessment → branch `2026-09-06-upstream-357-appsec-captcha-action` → stub PR #44 → tests + usage How-to → archive next.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Should empty-body AppSec `action: captcha` ban like empty `challenge`, or relay status with no body? | assumed — keep current relay (`handleAppsecResponseServeHTTP`); tests assert `http_status` (403 in the upstream example) and empty body, not the operator ban page. | explore |
| Fold captcha scenarios onto `core_plugin_appsec_bot-detection` or create a new spec? | assumed — MODIFIED on `core_plugin_appsec_bot-detection` (add parse + relay scenarios for `action: captcha`, including the no-body envelope). No new leaf. | explore |

## Before merge
- [ ] [P3] Archive OpenSpec change, drop WIP on PR #44
- [x] Usage How-to: empty captcha body still relays `http_status`
- [x] Five-axis code review (all axes none)
- [x] Add captcha JSON parse and bouncer relay tests
- [x] Propose OpenSpec change `appsec-captcha-action-tests`
- [x] Explore and prepare

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
| Reviewed head | de3f9b953d019e757c9ced2a2718588041be636e | Matches pushed usage-doc commit |

### Stored data model
None.

### Technical review
Best possible solution: tests lock current envelope parse and relay; usage How-to now names the empty-captcha vs empty-challenge split.

Do we have a high-confidence way to reproduce? Yes — three captcha unit tests plus the How-to line.

Is this the best way to solve the issue? Yes for add-tests scope.

### Evidence
What I checked:
- `devdocs-impact.md`: stale-usage produced on `core_plugin_appsec.md`
- Five-axis review remaining `none.`

### Rank-up moves
None.
