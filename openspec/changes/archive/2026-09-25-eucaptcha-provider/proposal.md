## Why

Operators cannot select EU CAPTCHA as a first-class captcha provider. Dest accepts `hcaptcha`, `recaptcha`, `recaptcha-enterprise`, `turnstile`, and `custom`; token `eucaptcha` is rejected at `ValidateParams`, and `New` has no widget/verifier pairing for it. Upstream proposed the same provider on the maxlerebourg tree at https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/317 (context only; that diff is not applied here).

## What Changes

- Accept provider value `eucaptcha` beside `hcaptcha`, `recaptcha`, `recaptcha-enterprise`, `turnstile`, and `custom`. Keep `recaptcha-enterprise`.
- `New` gains a pairing case (same place as `recaptcha-enterprise`): Widget `{ScriptURL: https://cdn.eu-captcha.eu/verify.js, Class: eu-captcha, TokenField: eu-captcha-response, RetryAfterReject: true}` and a new eucaptcha verifier. Do not put `eucaptcha` in `infoProviders`. `Validate` and `ServeHTTP` stay provider-blind.
- Stock `captcha.html` stays unchanged. Official `verify.js` injects `eu-captcha-response`. The checkbox branch already supplies class, `data-sitekey`, and `data-callback="captchaCallback"`.
- Server verify is not siteverify and not custom JSON. POST `https://api.eu-captcha.eu/v1/verify` with JSON `sitekey`, `secret`, `client_ip`, `client_token`, `client_user_agent`.
- Mint the gate cookie only when `Validate` returns `Pass`. The new verifier returns Pass-true only when HTTP 200 JSON has `success` true and `train` is JSON false or null. `train` true is Pass-false (no cookie).
- Forward `Validate`'s `remoteIP` (`clientRequest.remoteIP` after `GetRemoteIP` / `ipAddr.String()`) and `r.UserAgent()`. Do not parse forwarded headers in captcha. Do not put User-Agent on `clientRequest`. An empty client address is a reject on this verifier only (no vendor POST). An empty User-Agent is forwarded, not locally rejected.
- Widen `Verifier.Pass` to `Pass(token, remoteIP, userAgent string)`. Siteverify and assessments ignore `userAgent`. Empty token stays `None` (do not POST).
- `CaptchaSecretKey` stays required for `eucaptcha`. No `/verify-credentials` startup probe. `train` is the fail-closed path.
- README `CaptchaProvider` expected values include `eucaptcha`.

## Capabilities

### New Capabilities

- `core_plugin_middleware_captcha-eucaptcha-verify`: EU CAPTCHA `POST /v1/verify` JSON, identity owners (`GetRemoteIP` / `clientRequest.remoteIP`, `r.UserAgent()`), empty-address reject, `success`/`train` classification, Error vs Reject.

### Modified Capabilities

- `core_plugin_middleware_captcha-widget`: `New` pairing for `eucaptcha` (script, class, `TokenField`); `Validate` forwards `r.UserAgent()` into `Pass`.
- `core_plugin_middleware_config-validation`: `eucaptcha` stays on the secret-required list (not the enterprise empty-secret exception).
- `core_plugin_middleware_captcha-enterprise-config`: provider allowlist accepts `eucaptcha` and still accepts `recaptcha-enterprise`.

## Impact

- `pkg/configuration/configuration.go` (`EucaptchaProvider`, `validateCaptcha` allowlist, secret-required path)
- `pkg/captcha/captcha.go` (`New` case; `Validate` passes `r.UserAgent()`)
- `pkg/captcha/verifier.go` (`Pass` arity)
- `pkg/captcha/siteverify.go` / `pkg/captcha/assessments.go` (ignore `userAgent`)
- New `pkg/captcha/eucaptcha.go` (verifier owner)
- `pkg/captcha/gate.go` unchanged (mint still on `Pass`)
- `captcha.html` unchanged
- `README.md` provider list / `CaptchaProvider` expected values
- Configuration and captcha `zzz_` tests
- Do not port https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/317 (cache client, `FormValue`, Content-Type substring, HTTP 400 handling, provider branch inside `Validate`, startup credential log)
- Do not rewrite siteverify or assessments empty-address omit
- Do not add a startup `/verify-credentials` probe
