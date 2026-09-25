# Widget

## Language

**Widget**:
The challenge-page pairing stored at captcha construction (script URL, class, token field, action, boot script, retry-after-reject).
_Avoid_: provider name on the request path, operator-supplied boot string

**Verifier**:
The stored `Pass` implementation that classifies a posted solver token. Not named on `ServeHTTP` or `Validate`.
_Avoid_: provider switch in `ServeHTTP`

**Outcome**:
How `Validate` classifies a challenge request: `None`, `Pass`, or `Reject`. Error is the error return.
_Avoid_: `(bool, error)` as the `Validate` result, `(None, err)`

## Overview

`Client.New` is the only provider and key-type switch. It stores one Widget and one Verifier. `ServeHTTP` and `Validate` read those fields only. Siteverify encoding stays on `core_plugin_middleware_captcha-siteverify`. Assessments stay on `core_plugin_middleware_captcha-assessments`. Eucaptcha verify stays on `core_plugin_middleware_captcha-eucaptcha-verify`. Gate mint stays on `core_plugin_middleware_captcha-gate`.

## How to use

- Pair widget and verifier in `New`. Do not mention a provider name or key type in `ServeHTTP` or `Validate`.
- `Validate` returns `(Outcome, error)`. Non-POST or empty token is `None` (no `Pass` call). Verifier true is `Pass`. Verifier false with no error is `Reject`. Transport or undecodable provider body is the error return.
- `Validate` calls `Pass(token, remoteIP, r.UserAgent())`. Siteverify and assessments ignore `userAgent`. Do not put User-Agent on `clientRequest`.
- `Verifier.Pass` stays `(bool, error)` as the return.
- Eucaptcha: script `https://cdn.eu-captcha.eu/verify.js`, class `eu-captcha`, field `eu-captcha-response`, retry true. Pair the eucaptcha verifier. Do not put `eucaptcha` in `infoProviders`. Verify HTTP stays on `core_plugin_middleware_captcha-eucaptcha-verify`.
- On `Pass`: mint `crowdsec_captcha_gate`, set `solved-captcha` when configured, set `Cache-Control: no-cache, no-store`, 302 to the request URL.
- On `None` or error: set `Cache-Control: no-cache, no-store` next to `Content-Type` before `WriteHeader(200)`, then render the challenge with the stored boot script.
- On `Reject` with `RetryAfterReject`: same 200 headers and render with boot. On `Reject` without retry: same 200 headers, render, omit boot.
- Enterprise checkbox: `enterprise.js` with no `render=`, class `g-recaptcha`, field `g-recaptcha-response`, retry true.
- Enterprise score: `enterprise.js?render={siteKey}`, no checkbox class, same token field, retry false. Boot is fixed Go text (`grecaptcha.enterprise.ready` then `execute`, write the token, submit). Do not take boot from config.
- Stock `captcha.html` stays one file. Template map keeps `SiteKey`, `FrontendJS`, `FrontendKey`, `ChallengeURL` and adds `BootScript`, `Action`, `DrawCheckbox` (non-empty when the checkbox div should render).

## Pattern snippet

```go
if outcome == Reject && !c.widget.RetryAfterReject {
	bootScript = ""
}
rw.Header().Set("Content-Type", c.templateContentType)
rw.Header().Set("Cache-Control", "no-cache, no-store")
rw.WriteHeader(http.StatusOK)
```

## Key files

- `pkg/captcha/widget.go`
- `pkg/captcha/outcome.go`
- `pkg/captcha/verifier.go`
- `pkg/captcha/enterprise.go`
- `pkg/captcha/eucaptcha.go`
- `pkg/captcha/captcha.go` (`New`, `ServeHTTP`, `Validate`)
- `captcha.html`

## Gotchas

- Challenge HTML at 200, the Pass 302, and `WriteSolvedRedirect` use exactly `no-cache, no-store`. Do not add `private`, `max-age`, or `Pragma`. Ban-page Cache-Control lives on `core_plugin_middleware_ban-page`.
- A replaced checkbox template that omits the new keys still works when `FrontendJS` is `enterprise.js`. Score needs `BootScript`.
- Both enterprise key types keep field name `g-recaptcha-response`.
- Omit-boot after score reject is a product choice so the page does not auto-`execute` again.
- Eucaptcha TokenField is `eu-captcha-response`. Stock `captcha.html` does not hardcode that input; `verify.js` injects it.
