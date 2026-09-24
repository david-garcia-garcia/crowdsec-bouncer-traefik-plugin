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

`Client.New` is the only provider and key-type switch. It stores one Widget and one Verifier. `ServeHTTP` and `Validate` read those fields only. Siteverify encoding stays on `core_plugin_middleware_captcha-siteverify`. Assessments stay on `core_plugin_middleware_captcha-assessments`. Gate mint stays on `core_plugin_middleware_captcha-gate`.

## How to use

- Pair widget and verifier in `New`. Do not mention a provider name or key type in `ServeHTTP` or `Validate`.
- `Validate` returns `(Outcome, error)`. Non-POST or empty token is `None` (no `Pass` call). Verifier true is `Pass`. Verifier false with no error is `Reject`. Transport or undecodable provider body is the error return.
- `Verifier.Pass` stays `(bool, error)`.
- On `Pass`: mint `crowdsec_captcha_gate`, set `solved-captcha` when configured, 302 to the request URL.
- On `None` or error: render the challenge with the stored boot script.
- On `Reject` with `RetryAfterReject`: render with boot. On `Reject` without retry: render and omit boot.
- Enterprise checkbox: `enterprise.js` with no `render=`, class `g-recaptcha`, field `g-recaptcha-response`, retry true.
- Enterprise score: `enterprise.js?render={siteKey}`, no checkbox class, same token field, retry false. Boot is fixed Go text (`grecaptcha.enterprise.ready` then `execute`, write the token, submit). Do not take boot from config.
- Stock `captcha.html` stays one file. Template map keeps `SiteKey`, `FrontendJS`, `FrontendKey`, `ChallengeURL` and adds `BootScript`, `Action`, `DrawCheckbox` (non-empty when the checkbox div should render).

## Pattern snippet

```go
if outcome == Reject && !c.widget.RetryAfterReject {
	bootScript = ""
}
```

## Key files

- `pkg/captcha/widget.go`
- `pkg/captcha/outcome.go`
- `pkg/captcha/verifier.go`
- `pkg/captcha/enterprise.go`
- `pkg/captcha/captcha.go` (`New`, `ServeHTTP`, `Validate`)
- `captcha.html`

## Gotchas

- A replaced checkbox template that omits the new keys still works when `FrontendJS` is `enterprise.js`. Score needs `BootScript`.
- Both enterprise key types keep field name `g-recaptcha-response`.
- Omit-boot after score reject is a product choice so the page does not auto-`execute` again.
