## Motivation
Captcha remediation already ships hCaptcha, classic `recaptcha`, Turnstile, and `custom`. Classic `recaptcha` is `https://www.google.com/recaptcha/api.js` plus `POST https://www.google.com/recaptcha/api/siteverify` with `secret`, `response`, and optional `remoteip`. A solve counts only when the JSON body has `success: true`. A v2 checkbox that Google auto-migrated into a Cloud project still uses that exchange.

A key created in the Google Cloud reCAPTCHA console (Essentials, Standard, or Enterprise) does not. The browser must load `https://www.google.com/recaptcha/enterprise.js`. The server must `POST` `https://recaptchaenterprise.googleapis.com/v1/projects/{project}/assessments` and read `tokenProperties.valid`, then the action and `riskAnalysis.score` when those are set. Auth is a Cloud API key, not a siteverify shared secret.

The `custom` provider cannot stand in: its body is fixed as `secret`, `response`, and `remoteip`, and the pass bit is `success` only. There is no assessments URL, no Cloud API key header, and no score or action check. `Validate` is `(bool, error)` and `(false, nil)` means both "no token yet" and "provider said no", so a score-style page that auto-submits on load cannot stop after a refusal — it would render the same boot again. `ValidateParams` also demands `CaptchaSecretKey` whenever captcha is enabled, even though a Cloud key has no siteverify secret.

Left alone, operators who hold Cloud-issued checkbox or score keys cannot put those keys on this bouncer. They stay on classic v2 siteverify, another provider, or they cannot serve captcha with the keys they actually have.

Priority: P2 — operator pain with a workaround

## Implementation
`New` is the only switch on provider and key type. It stores a Widget (script, class, token field, action, boot, retry) and a Verifier `Pass(token, remoteIP)`. hCaptcha, classic `recaptcha`, Turnstile, and `custom` keep today's siteverify (`secret`+`response`+`success`, form vs JSON, Content-Type miss as Pass-false). `recaptcha-enterprise` pairs an assessments verifier with either a checkbox widget (`enterprise.js`, `g-recaptcha`, retry) or a score widget (`enterprise.js?render={siteKey}`, hidden `g-recaptcha-response`, fixed `grecaptcha.enterprise.ready` / `execute` boot, no retry).

The assessments verifier POSTs JSON `event.token`, `event.siteKey`, optional `event.userIpAddress` and `event.expectedAction` to `https://recaptchaenterprise.googleapis.com/v1/projects/{project}/assessments` on the existing captcha HTTP client. Auth is `X-Goog-Api-Key` only. Pass order is `tokenProperties.valid`, then action case-insensitively when set, then `riskAnalysis.score` when a minimum is set. Non-2xx, empty/non-JSON, or a Google error envelope without `tokenProperties` is an error; `valid` false is reject.

`Validate` returns `(Outcome, error)`: `None` (not POST or empty token, no verifier call), `Pass`, `Reject`. `ServeHTTP` still mints `crowdsec_captcha_gate` and 302s on Pass. None or error renders with boot. Reject with retry renders with boot. Reject without retry omits boot so a score page does not auto-execute again.

`ValidateParams` accepts `recaptcha-enterprise` and requires `captchaEnterpriseKeyType` (`checkbox` or `score`), project id, and API key (file-then-field). Score also requires action and a min-score string parsed `> 0` and `<= 1`. `CaptchaSecretKey` is not required for this provider. Stock `captcha.html` stays one file and gains `BootScript`, `Action`, and `DrawCheckbox`.

## What this changes
**Operators.** Set `captchaProvider: recaptcha-enterprise` plus `captchaEnterpriseKeyType` (`checkbox` or `score`), `captchaEnterpriseProjectId`, and `captchaEnterpriseApiKey` (or `captchaEnterpriseApiKeyFile`); score also needs `captchaEnterpriseAction` and `captchaEnterpriseMinScore`. `captchaSecretKey` is unused for this provider. Classic `recaptcha` stays `api.js` / siteverify. A replaced template that wants a score key must include the `BootScript` placeholder.

**Admin users.** None.

**Developers.** `Client.Validate` returns `(Outcome, error)` (`None`, `Pass`, `Reject`). `Client.New` takes a named `Enterprise` value. `configuration.Config` accepts `recaptcha-enterprise` and the `captchaEnterprise*` knobs. Challenge template data gains `BootScript`, `Action`, and `DrawCheckbox`.

**End users.** Behind `recaptcha-enterprise`, visitors complete a Cloud checkbox or an invisible score check; other providers still show the same checkbox.

## Merge readiness
Ready for review. 0 items remain.

Priority: P2 — operator pain with a workaround
Reviewed head: a8adf4dd
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Ready |
| CI proof | 6/6 | succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/36038103494 |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-24-recaptcha-enterprise pushed | `git` |
| OpenSpec | recaptcha-enterprise | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/149 | pr-host |
| CI | build 36038103494 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/36038103494 | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/36038103494 |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_middleware_captcha-assessments](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-recaptcha-enterprise/openspec/changes/recaptcha-enterprise/proposal.md) — added
- [core_plugin_middleware_captcha-enterprise-config](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-recaptcha-enterprise/openspec/changes/recaptcha-enterprise/proposal.md) — added
- [core_plugin_middleware_captcha-siteverify](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-recaptcha-enterprise/openspec/changes/recaptcha-enterprise/proposal.md) — modified
- [core_plugin_middleware_captcha-widget](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-recaptcha-enterprise/openspec/changes/recaptcha-enterprise/proposal.md) — added
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-recaptcha-enterprise/openspec/changes/recaptcha-enterprise/proposal.md) — modified
- [core_plugin_middleware_instance-slots](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-recaptcha-enterprise/openspec/changes/recaptcha-enterprise/proposal.md) — modified


## Deviations from the ask
- taken: Config and construction fields spelled `CaptchaEnterpriseProjectId`, `CaptchaEnterpriseApiKey`, `ApiKey`, `ProjectId`. → `CaptchaEnterpriseProjectID`, `CaptchaEnterpriseAPIKey`, `APIKey`, `ProjectID` (JSON tags stay `captchaEnterpriseProjectId` / `captchaEnterpriseApiKey`). — `pkg/configuration/configuration.go (LapiCapiMachineID, CaptchaGateBindIP, CaptchaCustomJsURL)` — honouring the task's Go spelling adds a second initialism style on the same Config surface.. Requester: not asked.


## Follow-up issues
None.

## How this fits together
Ticket 2026-09-24-recaptcha-enterprise on branch 2026-09-24-recaptcha-enterprise targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/149; CI build 36038103494 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/36038103494.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| What Go result does Validate expose for None / Pass / Reject / Error without ServeHTTP branching on provider? | bounded asked — changes existing Validate (bool, error); 1 production caller (ServeHTTP) and 4 tests in pkg/captcha/zzz_validate_body_test.go (roots worktree *.go) | assumed — (Outcome, error) with None, Pass, Reject. Error is the error return. Verifier.Pass stays (bool, error). ServeHTTP switches on Outcome plus widget.retry. | explore |


## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-recaptcha-enterprise/devstate/2026/09/2026-09-24-recaptcha-enterprise/codereview_standards.md) — 4 total, 0 pending, 4 completed
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-recaptcha-enterprise/devstate/2026/09/2026-09-24-recaptcha-enterprise/codereview_nitpicks.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-recaptcha-enterprise/devstate/2026/09/2026-09-24-recaptcha-enterprise/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-recaptcha-enterprise/devstate/2026/09/2026-09-24-recaptcha-enterprise/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-recaptcha-enterprise/devstate/2026/09/2026-09-24-recaptcha-enterprise/codereview_security.md) — 1 total, 0 pending, 0 completed, 1 skipped
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-recaptcha-enterprise/devstate/2026/09/2026-09-24-recaptcha-enterprise/codereview_performance.md) — 1 total, 0 pending, 1 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-recaptcha-enterprise/devstate/2026/09/2026-09-24-recaptcha-enterprise/codereview_dead.md) — 1 total, 0 pending, 1 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-recaptcha-enterprise/devstate/2026/09/2026-09-24-recaptcha-enterprise/codereview_coverage.md) — 4 total, 0 pending, 2 completed, 2 skipped


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 3 added / 3 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | a8adf4dd8c3d595b54c7687e17b5b847d07e4c17 | Card must match the branch you measured |

### Stored data model
None.
