## Context

See proposal.md. Dest `handleRemediationServeHTTP` (`pkg/bouncer/bouncer.go`) is `kind captcha AND Valid AND Method != HEAD` then `Check` → origin else `ServeHTTP`; everything else is ban. `Check` already reads the HMAC gate cookie only. First-solve POST already 302s inside `ServeHTTP`. `captchaResponseFromRequest` already reads query / POST form / raw body and restores `Body` (1MiB cap). Yaegi v0.16 loads `CreateConfig`/`New` from the module root; `pkg/captcha` is in-tree from bouncer. Stay out of `pkg/lapi` and `pkg/reclaim`.

## Goals / Non-Goals

**Goals:**
- Route captcha-kind requests in one handler: custom-resource pass, Check-true form POST 302, Check-true origin, else challenge (HEAD included).
- Keep form-post detect and resource match on `pkg/captcha.Client`.
- Add optional `captchaCustomChallengeUrl` without changing the four required custom fields.

**Non-Goals:**
- Cache keys or `{ip}_captcha` grace.
- Stream lease / `Cache().Acquire`.
- Generic `atomic.Pointer[T]` across packages.
- Rebase or merge of #48 / #50; template `ChallengeURL` wiring.
- Changing first-solve `ServeHTTP` 302.
- Passthrough on ban.

## Decisions

1. **Owner split.** `captcha.Client` owns `IsCaptchaFormPost` (POST + non-empty `captchaResponseFromRequest` for `infoProvider.response`) and `IsCustomResourceRequest` (exact path). `WriteSolvedRedirect` issues `StatusFound` to `req.URL.String()` and the `solved-captcha` remediation header when configured. Bouncer only sequences those calls. Alternative: inline readers in bouncer — rejected (`skill:sbs-dev-commandments:One job, one owner`; would add a second body reader).

2. **Routing order** (captcha + `Valid`):
   1. custom-resource path → `handleNextServeHTTP`
   2. `Check` true + form POST → `WriteSolvedRedirect`
   3. `Check` true → `handleNextServeHTTP`
   4. else → `captcha.ServeHTTP`
   Else ban. Custom-resource before `Check` so the widget loads without a cookie. `handleNextServeHTTP` keeps AppSec on. Alternative: skip AppSec on assets — rejected (passthrough must not become a bypass).

3. **Match set.** At `Client.New`, `url.Parse` `CaptchaCustomJsURL` and optional `captchaCustomChallengeUrl`; keep each path that is non-empty and starts with `/`. Compare to `req.URL.Path`. Ignore host and query. Custom-provider only; built-in CDN URLs are not stored. Never parse `CaptchaCustomValidateURL`. Alternative: prefix match — rejected (a request could smuggle `/admin` or a JS directory). Alternative: host+path — rejected (absolute config URLs would miss same-route assets).

4. **Optional key.** Add `CaptchaCustomChallengeURL` / `json:"captchaCustomChallengeUrl,omitempty"` on `configuration.Config`. Pass it into `Client.New` next to the JS URL. Empty = JsURL path only. Do not add it to `validateCaptcha` required fields. Do not add `ChallengeURL` to the template map.

5. **HEAD.** Drop `req.Method != http.MethodHead` from the captcha branch. Challenge `ServeHTTP` already no-ops `Validate` on non-POST, so HEAD without a cookie gets the same HTML as GET. Replace `TestCaptchaMethodBasedLogic` (it re-encodes `kind == captcha && Method != HEAD`) with handler tests.

6. **Identity and grace.** Reuse `req.remoteIP` already set by `ip.GetRemoteIP`. `Check(req.Request, req.remoteIP)` only. No cache client on captcha. No `atomic.Pointer[T]`. Process lifetime unchanged (per-request routing).

7. **Yaegi.** Do not change module-root `CreateConfig`/`New` signatures beyond the new optional config field on the existing struct. `captcha.Client.New` is not Yaegi-loaded; adding a `challengeURL string` parameter is in-tree only.

## Risks / Trade-offs

- [Passthrough as bypass] → exact path only; ban never matches; AppSec still runs; `CaptchaCustomValidateURL` excluded.
- [Second body reader on form POST] → reuse `captchaResponseFromRequest`; it already restores `Body`.
- [Operators with a hardcoded widget path] → they set optional `captchaCustomChallengeUrl`; empty keeps JsURL-only.
- [HEAD now returns captcha HTML instead of ban] → ticket Desired; old `TestCaptchaMethodBasedLogic` and #50 lose.

## Migration Plan

Deploy. Existing custom-provider configs keep working (JsURL path only). Operators who need a second widget path set `captchaCustomChallengeUrl`. Cite #48 and #50 on the PR body; do not merge those branches.

## Open Questions

None — explore assumed policies apply; FindSpecHost chose `core_plugin_middleware_captcha-routing`.
