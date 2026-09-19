# Requirement
IssueKey: 2026-09-17-captcha-request-routing

## Problem
`handleRemediationServeHTTP` has two holes (stale PRs #48 and #50, one ticket). After the gate cookie allows the visitor, a captcha-form POST is forwarded to origin as POST, so GET-only origins answer 405 (duplicate-tab submit after solve). Custom-provider challenge assets are themselves remediated, so the widget never loads. A HEAD on a captcha-remediated URL is excluded from the captcha branch and falls through to ban.

## Current (code)
- `handleRemediationServeHTTP`: captcha `Valid` + kind captcha + `Method != HEAD` → `Check` true calls `handleNextServeHTTP`; else `ServeHTTP`. Anything else is ban. `pkg/bouncer/bouncer.go`
- `Check` reads the HMAC gate cookie only. `pkg/captcha/captcha.go`
- First successful `Validate` already sets the gate cookie and 302s. `pkg/captcha/captcha.go`
- `captchaResponseFromRequest` reads query / POST form / raw body and restores `Body`. Unexported. `pkg/captcha/captcha.go`
- `IsCaptchaFormPost` / `WriteSolvedRedirect`: not found
- `TestCaptchaMethodBasedLogic` expects HEAD + captcha → ban fallback. `pkg/bouncer/zzz_bouncer_test.go`
- Custom provider stores `CaptchaCustomJsURL` as `infoProvider.js`. No challenge-URL field. `pkg/configuration/configuration.go` `pkg/captcha/captcha.go`
- `captchaCustomChallengeUrl` / `CaptchaCustomChallengeURL`: not found
- `IsCustomResourceRequest`: not found
- Captcha-gate spec owns cookie grace and the first-solve 302. It does not specify Check-path form POST, custom-resource passthrough, or HEAD. `openspec/specs/core_plugin_middleware_captcha-gate/spec.md`
- `core_plugin_captcha_solved-form-post` / `core_plugin_captcha_custom-resource-passthrough`: not found
- Bouncer spec does not name `handleRemediationServeHTTP` routing. `openspec/specs/core_plugin_middleware_bouncer/spec.md`
- `Client.New` takes `gateSecret` and `gateBindIP` (post-#58). `pkg/captcha/captcha.go` `pkg/bouncer/bouncer.go`

## Desired
- When the request is the captcha form POST and `Check` is true, 302 to the same URL. Do not forward that POST to origin. Detect the form via `captchaResponseFromRequest`; do not add a second body reader.
- Requests that target the configured custom challenge resources go to origin while the visitor is under captcha remediation. Ban stays blocked.
- HEAD is not excluded from the captcha path (treat like the GET it previews).
- Past-captcha is `Check(req, remoteIP)` and the cookie only. No cache keys for grace.
- Spec the routing rules of `handleRemediationServeHTTP`: which requests bypass remediation and why the passthrough scope is safe.
- Tests that fail before the fix.
- PR body cites #48 and #50 so those PRs can close when this lands.

## Affected
- `pkg/bouncer/bouncer.go` `handleRemediationServeHTTP`
- `pkg/bouncer/zzz_bouncer_test.go`
- `pkg/captcha` (reuse form-post detect; custom-resource match)
- `pkg/configuration` only if explore decides a challenge-URL key is required
- Spec leaves that own captcha routing (update captcha-gate and/or add a routing leaf)
- `knowledge/devdocs/core_plugin_middleware_captcha-gate.md`

## Out of scope
- `pkg/lapi`, stream lease, `Cache().Acquire`, `pkg/reclaim`
- Rebase or merge of #48 / #50
- Cache keys or `{ip}_captcha` grace
- `atomic.Pointer[T]`
- Closing #48 / #50 (reference only)
- Changing the first-solve `ServeHTTP` 302 (already correct)
- Ordinary POSTs that do not carry the provider response field (must still reach origin after solve)
- Passthrough on ban remediation
- #50's template `ChallengeURL` wiring as a must

## Unknowns
- Passthrough match set: `CaptchaCustomJsURL` path only, or also a widget/challenge URL. Ticket names both the script and the widget endpoint; dest has only JsURL as a browser-facing custom URL.
- Whether that needs a new optional public key. Ticket does not name one. Old #50 added `captchaCustomChallengeUrl`.
- Path vs host vs prefix matching. Ticket: scope to what the configured challenge URL needs, and say in the spec why that is safe.
- Export `captchaResponseFromRequest` vs a wrapper. Unexported today.
- HEAD-like-GET for every captcha URL, or only custom-resource paths. Ticket: HEAD is not excluded from the captcha path.

## Tensions
- Ticket Problem 1 reads as "the request that carries the solution" forwarded as POST. First-solve POST already 302s in `ServeHTTP`. The remaining hole is `Check` true plus captcha-form POST (duplicate tab), which is what #48 fixed.
- Ticket: HEAD treated like GET on the captcha path. Current test and old #50 assumed non-matching captcha HEAD stays ban.
- Ticket forbids cache grace; captcha-gate already forbids it. Old branches wrote `{ip}_captcha`.
- Ticket DoD: write routing rules into spec leaves. The #48/#50 leaves never landed on dest.
- Old #50 added `captchaCustomChallengeUrl` and template `ChallengeURL`. This ticket does not name either. Not Desired.
