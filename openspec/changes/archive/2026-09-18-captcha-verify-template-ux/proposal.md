## Why

Dest siteverify omits the bouncer-resolved client address, so providers never see `remoteip`. Transport and JSON-decode failures become a bare HTTP 400. A set `captchaProvider` with an empty `captchaFilePath` boots, then `Client.New` discards `GetTemplate` and the first challenge panics.

## What Changes

- Thread the `remoteIP` already passed into `ServeHTTP` into `Validate(r, remoteIP)` and POST form field `remoteip` with `secret` and `response`. Do not re-parse forwarded headers in captcha.
- On siteverify transport or JSON decode failure, log and re-render captcha HTML at HTTP 200. Keep `(false, nil)` for empty token, `success:false`, and non-JSON Content-Type.
- When `CaptchaProvider` is set, `ValidateParams` fails if `CaptchaFilePath` is empty or `GetTemplate` fails. `Client.New` returns the `GetTemplate` error. No bundled template. Ban template stays "when path is set".
- Tests that blank `CaptchaFilePath` to skip `GetTemplate` get a readable fixture file.
- Keep dest `crowdsec_captcha_gate` HMAC cookie, void `cache.Set`, #94 Content-Type rule, and `Client.New` without cache. Do not reuse declined PR #28.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_captcha-siteverify`: POST `remoteip` from the already-resolved `ServeHTTP` `remoteIP`; transport and JSON-decode failures re-render the 200 challenge instead of a bare 400.
- `core_plugin_middleware_config-validation`: when `captchaProvider` is set, require a non-empty loadable `captchaFilePath`; `Client.New` returns the `GetTemplate` error. Ban template stays "when path is set".

## Impact

- `pkg/captcha/captcha.go` (`Validate` signature and body, `ServeHTTP` error path, `New`)
- `pkg/configuration/configuration.go` (`validateEnabledCaptchaSettings` empty-path early return)
- Captcha and configuration tests that blank `CaptchaFilePath` or assert 400 on provider errors
- Specs `core_plugin_middleware_captcha-siteverify` and `core_plugin_middleware_config-validation`
- This change takes `knowledge/debt/2026-09-18-captcha-nil-template-panic.md` at apply
