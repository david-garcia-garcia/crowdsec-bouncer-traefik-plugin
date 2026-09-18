## Context

See proposal.md. Dest `handleRemediationServeHTTP` (`pkg/bouncer/bouncer.go`) is `kind captcha AND Valid AND Method != HEAD` then `Check` → origin else `ServeHTTP`; everything else is ban. `Check` already reads the HMAC gate cookie only. First-solve POST already 302s inside `ServeHTTP`. `captchaResponseFromRequest` already reads query / POST form / raw body and restores `Body` (1MiB cap). Yaegi v0.16 loads `CreateConfig`/`New` from the module root; `pkg/captcha` is in-tree from bouncer. Stay out of `pkg/lapi` and `pkg/reclaim`.

## Goals / Non-Goals

**Goals:**
- Route captcha-kind requests in one handler: custom-resource pass, Check-true form POST 302, Check-true origin, else challenge (HEAD included).
- Keep form-post detect and resource match on `pkg/captcha.Client`.
- Add optional `captchaCustomChallengeUrl` without changing the four required custom fields.

**Non-Goals:**
- Cache keys or `{ip}_captcha` grace, including #48's IP-keyed grace-cache notion of solved.
- Stream lease / `Cache().Acquire`.
- Generic `atomic.Pointer[T]` across packages.
- Rebase or merge of the #48 / #50 branches (their intent is reimplemented here instead).
- Changing first-solve `ServeHTTP` 302 or the bundled default `captcha.html`.
- Passthrough on ban.

## Decisions

1. **Owner split.** `captcha.Client` owns `IsCaptchaFormPost` (POST + non-empty `infoProvider.response` in the body) and `IsCustomResourceRequest` (exact path). `WriteSolvedRedirect` issues `StatusFound` to `req.URL.String()` and the `solved-captcha` remediation header when configured. Bouncer only sequences those calls. Alternative: inline readers in bouncer — rejected (`skill:sbs-dev-commandments:One job, one owner`).

2. **Routing order** (captcha + `Valid`):
   1. custom-resource path → `handleNextServeHTTP`
   2. `Check` true + form POST → `WriteSolvedRedirect`
   3. `Check` true → `handleNextServeHTTP`
   4. else → `captcha.ServeHTTP`
   Else ban. Custom-resource before `Check` so the widget loads without a cookie. `handleNextServeHTTP` keeps AppSec on. Alternative: skip AppSec on assets — rejected (passthrough must not become a bypass).

3. **Match set.** `configuration.CustomCaptchaResourcePath` is the one owner that turns a configured value into a browser path (`url.Parse`, keep a path that starts with `/`). `Client.New` calls it for `CaptchaCustomJsURL` and optional `captchaCustomChallengeUrl` and compares the stored paths to `req.URL.Path`. Ignore host and query. Custom-provider only; built-in CDN URLs are not stored. Never parse `CaptchaCustomValidateURL`. Alternative: a private copy of the rule in `pkg/captcha` — rejected, validation and matching would be free to disagree. Alternative: prefix match — rejected (a request could smuggle `/admin` or a JS directory). Alternative: host+path — rejected (absolute config URLs would miss same-route assets).

4. **Optional key.** Add `CaptchaCustomChallengeURL` / `json:"captchaCustomChallengeUrl,omitempty"` on `configuration.Config`. Pass it into `Client.New` next to the JS URL. Empty = JsURL path only, and stays out of `validateCaptcha` required fields. `validateEnabledCaptchaSettings` (master's owner, kept over this branch's rival `validateConfiguredCaptcha`) rejects a non-empty custom-provider value that names no absolute path, since it could never match a request. Built-in providers ignore the key.

5. **Template `ChallengeURL`.** The execute map gains `ChallengeURL` beside `SiteKey` / `FrontendJS` / `FrontendKey`, filled for the custom provider only. Without it the config key is unrenderable and the feature is half-finished. `examples/custom-captcha` uses it (compose label, `captcha.html`, README) and `README.md` documents the key. The bundled default `captcha.html` is untouched; CDN providers have no challenge endpoint. Captcha templates are compiled with `{{` / `}}` (`configuration.GetTemplate`), unlike the ban template's `[[` / `]]`.

6. **Form detection is its own reader.** `IsCaptchaFormPost` runs on requests that may still be forwarded, so it cannot reuse `captchaResponseFromRequest`: that reader serves `Validate` on a request the plugin answers itself and is free to `ParseForm` and truncate at 1MiB. The detector instead caps at 64KiB (`captchaFormMaxBytes` — a provider token is never that big), handles urlencoded and multipart, answers from `PostForm` when something upstream already parsed the form, and restores `Body` plus `ContentLength` whenever it answers no. A declared `Content-Length` over the cap short-circuits before any buffering; an unknown length is caught by peeking one byte past the cap and putting the peek back in front of the remainder. Alternative: one shared helper with a flag — rejected, the two callers want opposite body guarantees.

7. **HEAD (ratified).** Drop `req.Method != http.MethodHead` from the captcha branch. A HEAD from a client carrying a captcha remediation gets the captcha challenge page, not the ban page; the owner ratified this, reversing what #50 proposed. Challenge `ServeHTTP` already no-ops `Validate` on non-POST, so HEAD without a cookie gets the same HTML as GET. `TestCaptchaMethodBasedLogic` (it re-encoded `kind == captcha && Method != HEAD`) is replaced by `TestHandleRemediationServeHTTP_captchaHEADServesChallengePage`, which asserts the rule positively. A HEAD on a custom-resource path still reaches origin.

8. **Identity and grace.** Reuse `req.remoteIP` already set by `ip.GetRemoteIP`. `Check(req.Request, req.remoteIP)` only — the HMAC gate cookie, never #48's IP-keyed grace cache. No cache client on captcha. No `atomic.Pointer[T]`. Process lifetime unchanged (per-request routing).

9. **Yaegi.** Do not change module-root `CreateConfig`/`New` signatures beyond the new optional config field on the existing struct. `captcha.Client.New` is not Yaegi-loaded; adding a `challengeURL string` parameter is in-tree only.

## Risks / Trade-offs

- [Passthrough as bypass] → exact path only; ban never matches; AppSec still runs; `CaptchaCustomValidateURL` excluded.
- [Two provider-token readers to keep straight] → one caller each, named in their doc comments: `captchaResponseFromRequest` for first verify only, `IsCaptchaFormPost` for routing a request that may still be forwarded.
- [A captcha token inside an over-cap upload is missed] → accepted; a real token is never that big, and losing the upload body to origin is the worse failure.
- [Operators with a hardcoded widget path] → they set optional `captchaCustomChallengeUrl`; empty keeps JsURL-only.
- [HEAD now returns captcha HTML instead of ban] → owner-ratified; old `TestCaptchaMethodBasedLogic` and #50's proposal lose.
- [New validation error on a malformed challenge URL] → only on a non-empty value under the custom provider; the silent alternative is a key that never matches.

## Migration Plan

Deploy. Existing custom-provider configs keep working (JsURL path only). Operators who need a second widget path set `captchaCustomChallengeUrl`. #48 and #50 close in favour of this PR at the owner's direction; their branches are not merged.

## Open Questions

None — explore assumed policies apply; FindSpecHost chose `core_plugin_middleware_captcha-routing`.
