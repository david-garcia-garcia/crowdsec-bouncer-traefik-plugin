## Why

Operators using `captchaProvider=custom` with CapJS Standalone cannot verify solved challenges: `pkg/captcha.Client.Validate` always POSTs urlencoded `secret` and `response`. Cap Standalone `/siteverify` requires `Content-Type: application/json` with the same keys. Wicketkeeper-style form verify must keep working.

## What Changes

- Add public `captchaCustomValidateBody` (`form` | `json`). Empty defaults to `form` (today’s `PostForm`).
- When `captchaProvider` is `custom` and the body is `json`, the plugin POSTs JSON `{"secret","response"}` to `CaptchaCustomValidateURL`.
- Built-in hCaptcha / reCAPTCHA / Turnstile stay urlencoded regardless of the field.
- Document the knob and a CapJS JSON example. No new CapJS docker stack. No extra verify fields, headers, or `remoteip`.

## Capabilities

### New Capabilities

- `core_plugin_captcha_custom-verify`: Custom provider siteverify body encoding (`form` vs `json`) so CapJS Standalone works without a sidecar adapter.

### Modified Capabilities

None.

## Impact

- `pkg/configuration` — new field, constants, `validateCaptcha`.
- `pkg/captcha` — `Validate` JSON vs form; `New` takes the body format.
- `pkg/bouncer` — pass the config field into `captcha.Client.New`.
- README, `examples/custom-captcha/README.md`.
- Unit tests in `pkg/captcha` and configuration validate.
