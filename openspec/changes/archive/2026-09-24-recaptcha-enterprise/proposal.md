## Why

A key created in the Google Cloud reCAPTCHA console does not use classic `api.js` / `siteverify`. Classic `captchaProvider=recaptcha` stays on that exchange; `custom` cannot stand in because its body is `secret`+`response` and its pass bit is `success`. Operators need a provider that loads `enterprise.js` and calls Cloud assessments.

## What Changes

- Add provider token `recaptcha-enterprise` with checkbox and score key types. Classic `recaptcha` is unchanged.
- Construction stores a Widget and a Verifier. `New` is the only switch on provider and key type. `ServeHTTP` and `Validate` do not mention a provider name.
- `Validate` returns `(Outcome, error)`: `None` (not POST or empty token), `Pass`, `Reject`. Transport and undecodable bodies stay the error return. `Verifier.Pass` stays `(bool, error)`.
- Siteverify stays one implementation for hCaptcha, classic `recaptcha`, Turnstile, and `custom` (`secret`+`response`+`success`, form vs JSON unchanged).
- Assessment is the second `Pass` implementation: `POST` JSON to `https://recaptchaenterprise.googleapis.com/v1/projects/{project}/assessments` with `X-Goog-Api-Key`. Pass order is `tokenProperties.valid`, then action (case-insensitive) when configured, then `riskAnalysis.score` when a minimum is set. `event.userIpAddress` is `GetRemoteIP` / `clientRequest.remoteIP` already passed into `Validate` / `Pass`.
- Score reject omits the boot script so the page does not auto-`execute` again. Checkbox reject re-renders with boot.
- Stock `captcha.html` stays one file. Template map gains `BootScript`, `Action`, `DrawCheckbox`.
- New knobs: `captchaEnterpriseKeyType`, `captchaEnterpriseProjectId`, `captchaEnterpriseApiKey` (file twin), `captchaEnterpriseAction`, `captchaEnterpriseMinScore` (string on Config). They join the captcha ownership payload.
- **BREAKING** for new `recaptcha-enterprise` startups only: `CaptchaSecretKey` is not required for that provider. hCaptcha, classic `recaptcha`, Turnstile, and `custom` still require it.

## Capabilities

### New Capabilities

- `core_plugin_middleware_captcha-assessments`: Cloud assessments `Pass` for `recaptcha-enterprise` (request JSON, header auth, valid / action / score, Error vs Reject).
- `core_plugin_middleware_captcha-widget`: Widget pairing, `Validate` outcomes, ServeHTTP render / retry / omit-boot, stock template placeholders.
- `core_plugin_middleware_captcha-enterprise-config`: Provider token and enterprise knobs at `ValidateParams` (key type, project, API key, action, min score).

### Modified Capabilities

- `core_plugin_middleware_config-validation`: Empty `CaptchaSecretKey` is rejected only when the provider is not `recaptcha-enterprise`. Site key and gate secret stay required.
- `core_plugin_middleware_captcha-siteverify`: `Validate` no longer returns `(bool, error)`. Empty token is `None` (no siteverify POST). Siteverify `Pass` and Content-Type miss stay as today.
- `core_plugin_middleware_instance-slots`: Captcha ownership Open key includes the enterprise knobs.

## Impact

- `pkg/configuration/configuration.go` (provider allowlist, secret carve-out, enterprise knobs, `GetVariable` for the API key)
- `pkg/captcha/captcha.go` (Widget, Verifier, `Validate` outcomes, ServeHTTP retry / omit-boot)
- `pkg/captcha/session.go` (`ownership` fields, `newOwnerClient` construction)
- `captcha.html` (boot / action / checkbox placeholders)
- `README.md` (provider token and knobs)
- Captcha and configuration `zzz_` tests; existing `Client.New` and `Validate` call sites
- Do not add a Google client library, a second template file, or change gate / routing / `IsCaptchaFormPost`
