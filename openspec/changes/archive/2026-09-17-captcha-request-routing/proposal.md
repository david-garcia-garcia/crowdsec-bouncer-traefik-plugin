## Why

`handleRemediationServeHTTP` has three holes after a captcha verdict: a solved-form POST with a valid gate cookie is forwarded to origin as POST (GET-only origins answer 405), same-origin custom challenge assets are themselves remediated (widget never loads), and captcha-kind HEAD is excluded from the captcha branch and falls through to ban. Dest already owns first-solve 302 and cookie-only `Check`; these remaining routes are unspecified.

## What Changes

- When kind is captcha and `Check` is true, a captcha-form POST 302s to the same URL. Do not forward that POST to origin. Detection is its own reader on `captcha.Client`: 64KiB cap, urlencoded and multipart, a fast path when the form was already parsed, and body restored whenever the request turns out not to be a captcha form. `captchaResponseFromRequest` stays the first-verify reader only — the two callers do not share one helper.
- Requests whose path matches a configured custom challenge resource go to origin while the visitor is under captcha remediation. Ban stays blocked. Passthrough uses `handleNextServeHTTP` (AppSec still runs). Exact path only — not a prefix, not a host match, not `CaptchaCustomValidateURL`.
- Optional public key `captchaCustomChallengeUrl` / `CaptchaCustomChallengeURL` names a second browser path. Empty = `CaptchaCustomJsURL` path only. Custom-provider validation still requires the existing four fields only, and rejects a non-empty value that names no absolute path.
- Wire template `ChallengeURL` so an operator can actually render the endpoint: captcha execute map, `examples/custom-captcha` (compose label, `captcha.html`, README) and a `README.md` entry. The bundled default `captcha.html` is unchanged.
- HEAD is not excluded from the captcha path: a HEAD from a client carrying a captcha remediation gets the captcha challenge page, never the ban page. Ratified by the owner; asserted by a named test.
- Past-captcha stays `Check(req, remoteIP)` and the HMAC gate cookie only. No cache keys for captcha grace. Do not touch the stream lease or `Cache().Acquire`. Yaegi v0.16: no generic `atomic.Pointer[T]` across packages.
- Spec the routing table of `handleRemediationServeHTTP` on a new leaf. Keep `core_plugin_middleware_captcha-gate` as cookie / first-solve owner.
- Tests that fail before the fix. At the owner's direction this change folds in the parts #48 and #50 had that it was missing, so both close in its favour: #48's form-detection semantics (not its IP-keyed grace cache) and #50's operator-facing challenge-URL wiring.

## Capabilities

### New Capabilities

- `core_plugin_middleware_captcha-routing`: `handleRemediationServeHTTP` captcha-kind routing — solved-form POST 302, exact-path custom-resource passthrough (not a ban bypass), HEAD on the captcha path, optional `captchaCustomChallengeUrl`.

### Modified Capabilities

- None. Cookie grace and first-solve 302 stay on `core_plugin_middleware_captcha-gate`. Bouncer `New` / stream ownership stay on `core_plugin_middleware_bouncer`. `ValidateParams` required custom fields stay on `core_plugin_middleware_config-validation`.

## Impact

- `pkg/bouncer` (`handleRemediationServeHTTP` routing; replace tautological `TestCaptchaMethodBasedLogic`)
- `pkg/captcha` (`IsCaptchaFormPost` plus its own capped body reader, custom-resource match, `WriteSolvedRedirect`, template `ChallengeURL`)
- `pkg/configuration` (optional `captchaCustomChallengeUrl`; `CustomCaptchaResourcePath` as the one resource-path owner, folded into `validateEnabledCaptchaSettings`)
- `README.md` and `examples/custom-captcha/` (compose label, `captcha.html`, README)
- New spec leaf `openspec/specs/core_plugin_middleware_captcha-routing/`
- Stay out of `pkg/lapi`, `pkg/appsec`, `pkg/cache` and `pkg/reclaim`
