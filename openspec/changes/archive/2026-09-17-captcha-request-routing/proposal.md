## Why

`handleRemediationServeHTTP` has three holes after a captcha verdict: a solved-form POST with a valid gate cookie is forwarded to origin as POST (GET-only origins answer 405), same-origin custom challenge assets are themselves remediated (widget never loads), and captcha-kind HEAD is excluded from the captcha branch and falls through to ban. Dest already owns first-solve 302 and cookie-only `Check`; these remaining routes are unspecified.

## What Changes

- When kind is captcha and `Check` is true, a captcha-form POST 302s to the same URL. Do not forward that POST to origin. Detect the form via existing `captchaResponseFromRequest`; do not add a second body reader.
- Requests whose path matches a configured custom challenge resource go to origin while the visitor is under captcha remediation. Ban stays blocked. Passthrough uses `handleNextServeHTTP` (AppSec still runs). Exact path only — not a prefix, not a host match, not `CaptchaCustomValidateURL`.
- Optional public key `captchaCustomChallengeUrl` / `CaptchaCustomChallengeURL` names a second browser path. Empty = `CaptchaCustomJsURL` path only. Custom-provider validation still requires the existing four fields only. Do not wire template `ChallengeURL`.
- HEAD is not excluded from the captcha path (treat like the GET it previews on every captcha-kind URL).
- Past-captcha stays `Check(req, remoteIP)` and the HMAC gate cookie only. No cache keys for captcha grace. Do not touch the stream lease or `Cache().Acquire`. Yaegi v0.16: no generic `atomic.Pointer[T]` across packages.
- Spec the routing table of `handleRemediationServeHTTP` on a new leaf. Keep `core_plugin_middleware_captcha-gate` as cookie / first-solve owner.
- Tests that fail before the fix. PR body cites #48 and #50 so those PRs can close when this lands.

## Capabilities

### New Capabilities

- `core_plugin_middleware_captcha-routing`: `handleRemediationServeHTTP` captcha-kind routing — solved-form POST 302, exact-path custom-resource passthrough (not a ban bypass), HEAD on the captcha path, optional `captchaCustomChallengeUrl`.

### Modified Capabilities

- None. Cookie grace and first-solve 302 stay on `core_plugin_middleware_captcha-gate`. Bouncer `New` / stream ownership stay on `core_plugin_middleware_bouncer`. `ValidateParams` required custom fields stay on `core_plugin_middleware_config-validation`.

## Impact

- `pkg/bouncer` (`handleRemediationServeHTTP` routing; replace tautological `TestCaptchaMethodBasedLogic`)
- `pkg/captcha` (`IsCaptchaFormPost`, custom-resource match, `WriteSolvedRedirect`; reuse `captchaResponseFromRequest`)
- `pkg/configuration` (optional `captchaCustomChallengeUrl` only)
- New spec leaf `openspec/specs/core_plugin_middleware_captcha-routing/`
- Stay out of `pkg/lapi` and `pkg/reclaim`
