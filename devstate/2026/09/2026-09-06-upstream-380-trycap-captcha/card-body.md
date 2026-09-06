Developer review: in progress — 2026-09-06T15:50:10Z

IssueKey: 2026-09-06-upstream-380-trycap-captcha
JobName: 2026-09-06-upstream-380-trycap-captcha

[sgsi-dev-ticket-status:2026-09-06-upstream-380-trycap-captcha]

## What this changes
**Operators.** Set `captchaProvider: trycap` and `captchaTrycapInstanceUrl` (Cap Standalone origin) plus existing site/secret keys. Default `captcha.html` renders `<cap-widget>`.

**Admin users.** None.

**Developers.** `pkg/captcha` JSON siteverify for trycap, empty trycap `FrontendKey`, `CapApiEndpoint` template slot, unit tests in `pkg/captcha/captcha_test.go`, spec `core_plugin_captcha_trycap-provider`.

**End users.** When an operator enables trycap, blocked clients see a Cap Standalone checkbox instead of hcaptcha/recaptcha/turnstile.

## Motivation
On `master`, operators who self-host TryCap Cap Standalone cannot select it as a built-in captcha provider. The plugin only verifies captchas via urlencoded `PostForm`, while Cap Standalone expects JSON `{"secret","response"}` at `/<site_key>/siteverify` with a `cap-token` field — so TryCap fails unless the operator runs an external adapter. Without this change, self-hosted TryCap remains unsupported despite upstream feature request #380.

## Merge readiness
Usage packet `core_plugin_captcha` already matches the apply; no produce. CI on HEAD is still running.

Priority: P2 — real operator pain with a workaround (external adapter or misconfigured custom provider).
Reviewed head: 112b9b8
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | CI in progress on reviewed head |
| CI proof | 3/6 | Main Process and both e2e jobs in progress |
| Local tests proof | N/A | Remote PR; CI covers |
| Review resolution | 6/6 | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-upstream-380-trycap-captcha pushed | git / GitHub |
| OpenSpec | trycap-captcha-provider | openspec/changes/trycap-captcha-provider/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/40 | pr-host |
| CI | build 34043535170 in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34043535170 | pull_request_read get_check_runs |
| Local tests | passed | handoff.yaml localTests (`go test` pkg/captcha, configuration, bouncer) |
| PR comments | no comments | comments.md absent |

## Specs
- [core_plugin_captcha_trycap-provider](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-upstream-380-trycap-captcha/openspec/changes/trycap-captcha-provider/proposal.md) — added

## Follow-up issues
- [ ] [note] [large] custom provider JSON siteverify (upstream #318) — TryCap needs JSON; `custom` still PostForms. Not taken: out of scope for this change.

## How this fits together
Local ticket (upstream #380) → branch `2026-09-06-upstream-380-trycap-captcha` → PR #40 → trycap provider landed → five-axis review applied → usage packet already current → CI running on 112b9b8.

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
- [ ] Wait for CI on reviewed head 112b9b8
- [x] Add `trycap` provider, JSON siteverify, default-template Cap branch, and unit tests
- [x] Five-axis review; empty trycap FrontendKey and infoProvider comment

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
| Reviewed head | 112b9b822b5996a176b584797de690ddad6a981c | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: First-class `trycap` with derived instance URLs and JSON verify, without changing `custom`.

Do we have a high-confidence way to reproduce? Yes — unit tests POST JSON to `{instance}/{siteKey}/siteverify` and keep hcaptcha on PostForm.

Is this the best way to solve the issue? Yes — a built-in matches hcaptcha/recaptcha/turnstile; `custom` cannot speak JSON.

### Evidence
What I checked:
- Devdocs impact: Captcha Client packet already has trycap How-to, Language, and Gotchas; findings none
- Five-axis review complete (see Axis review)
- PR #40 CI: Main Process 34043535170 and e2e 34043535099 in progress

### Rank-up moves
None.
