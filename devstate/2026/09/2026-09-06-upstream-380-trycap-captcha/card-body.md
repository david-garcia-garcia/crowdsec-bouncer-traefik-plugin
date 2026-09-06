Developer review: ready for review — 2026-09-06T15:57:03Z

IssueKey: 2026-09-06-upstream-380-trycap-captcha
JobName: 2026-09-06-upstream-380-trycap-captcha

[sgsi-dev-ticket-status:2026-09-06-upstream-380-trycap-captcha]

## What this changes
**Operators.** Set `captchaProvider: trycap` and `captchaTrycapInstanceUrl` (Cap Standalone origin) plus existing site/secret keys. Default `captcha.html` renders `<cap-widget>`.

**Admin users.** None.

**Developers.** `pkg/captcha` JSON siteverify for trycap, empty trycap `FrontendKey`, `CapApiEndpoint` template slot, unit tests in `pkg/captcha/captcha_test.go`, baseline spec `core_plugin_captcha_trycap-provider`.

**End users.** When an operator enables trycap, blocked clients see a Cap Standalone checkbox instead of hcaptcha/recaptcha/turnstile.

## Motivation
On `master`, operators who self-host TryCap Cap Standalone cannot select it as a built-in captcha provider. The plugin only verifies captchas via urlencoded `PostForm`, while Cap Standalone expects JSON `{"secret","response"}` at `/<site_key>/siteverify` with a `cap-token` field — so TryCap fails unless the operator runs an external adapter. Without this change, self-hosted TryCap remains unsupported despite upstream feature request #380.

## Merge readiness
Ready for review. 0 items remain.

Priority: P2 — real operator pain with a workaround (external adapter or misconfigured custom provider).
Reviewed head: c5d7fd7
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | CI succeeded; no open PR comments |
| CI proof | 6/6 | Main Process and both e2e jobs succeeded |
| Local tests proof | N/A | Remote PR; CI covers |
| Review resolution | 6/6 | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-upstream-380-trycap-captcha pushed | git / GitHub |
| OpenSpec | trycap-captcha-provider archived | openspec/changes/archive/2026-09-06-trycap-captcha-provider/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/40 | pr-host |
| CI | build 34043726387 success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34043726387 | pull_request_read get_check_runs |
| Local tests | passed | handoff.yaml localTests (`go test` pkg/captcha, configuration, bouncer) |
| PR comments | no comments | comments.md absent |

## Specs
- [core_plugin_captcha_trycap-provider](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-380-trycap-captcha/openspec/changes/archive/2026-09-06-trycap-captcha-provider/proposal.md) — added

## Follow-up issues
- [ ] [note] [large] custom provider JSON siteverify (upstream #318) — TryCap needs JSON; `custom` still PostForms. Not taken: out of scope for this change.

## How this fits together
Local ticket (upstream #380) → branch `2026-09-06-upstream-380-trycap-captcha` → PR #40 → trycap provider landed → five-axis review applied → usage packet current → OpenSpec archived → CI green.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| What is the official product name for the provider enum and docs — TryCap, Cap, or Cap Standalone? | assumed — enum `trycap`; README says Cap Standalone (trycap.dev) and key `captchaTrycapInstanceUrl` | explore |
| Where does the widget JavaScript load from — the instance or a CDN? | assumed — jsDelivr `cap-widget@0.1.57` as `type="module"`; instance URL is API only | explore |
| Does instance URL belong in a dedicated config key or reuse CaptchaCustomValidateURL? | assumed — dedicated `captchaTrycapInstanceUrl` | explore |
| Can default captcha.html serve all providers, or does TryCap need a separate template? | assumed — one default template with a Cap widget branch | explore |
| Does Cap siteverify accept recaptcha-style form-urlencoded, so PostForm would work? | assumed — no; documented contract is JSON | explore |
| Should this change also make `custom` POST JSON (upstream #318 CapJS)? | assumed — no; note as follow-up | explore |
| Must CI e2e run a live `tiago2/cap` container? | assumed — no; unit tests prove verify | explore |

## Before merge
None.

## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-380-trycap-captcha/devstate/2026/09/2026-09-06-upstream-380-trycap-captcha/codereview_standards.md) — 6 total, 0 pending, 2 completed, 4 skipped
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-380-trycap-captcha/devstate/2026/09/2026-09-06-upstream-380-trycap-captcha/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-380-trycap-captcha/devstate/2026/09/2026-09-06-upstream-380-trycap-captcha/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-380-trycap-captcha/devstate/2026/09/2026-09-06-upstream-380-trycap-captcha/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-380-trycap-captcha/devstate/2026/09/2026-09-06-upstream-380-trycap-captcha/codereview_dead.md) — 0 total, 0 pending, 0 completed

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 1 added / 0 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | c5d7fd7f57ac1e5283248881e6c1eb38421bfc83 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: First-class `trycap` with derived instance URLs and JSON verify, without changing `custom`.

Do we have a high-confidence way to reproduce? Yes — unit tests POST JSON to `{instance}/{siteKey}/siteverify` and keep hcaptcha on PostForm.

Is this the best way to solve the issue? Yes — a built-in matches hcaptcha/recaptcha/turnstile; `custom` cannot speak JSON.

### Evidence
What I checked:
- One OPEN PR #40 titled `✨ feat(captcha): add Cap Standalone trycap provider`
- CI on c5d7fd7: Main Process success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34043726387 ; e2e success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34043726381
- OpenSpec archived at `openspec/changes/archive/2026-09-06-trycap-captcha-provider/`

### Rank-up moves
None.
