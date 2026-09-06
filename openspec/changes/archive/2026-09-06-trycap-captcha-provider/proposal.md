## Why

Operators who self-host Cap Standalone (trycap.dev) cannot use it as a first-class captcha provider. This plugin only `PostForm`s urlencoded `secret`+`response` and the default template is a class-based widget, while Cap requires JSON siteverify and a `<cap-widget>` pointed at `{instance}/{siteKey}/`.

## What Changes

- Add `captchaProvider` value `trycap` next to `hcaptcha`, `recaptcha`, `turnstile`, and `custom`.
- Add public `captchaTrycapInstanceUrl` (Cap Standalone origin). Derive widget endpoint `{instance}/{siteKey}/` and verify URL `{instance}/{siteKey}/siteverify`.
- Reuse existing `captchaSiteKey` / `captchaSecretKey`.
- `trycap` verify POSTs JSON `{"secret","response"}` with `Content-Type: application/json` and reads form field `cap-token`. Other providers keep `PostForm`.
- Default `captcha.html` gains a Cap widget branch when the template is given a Cap API endpoint; SaaS widgets stay on the class+callback div.
- Unit tests cover JSON verify, URL join, and missing token. README and an example document operator wiring.
- Not **BREAKING**. `custom` is unchanged (no JSON siteverify).

## Capabilities

### New Capabilities

- `core_plugin_captcha_trycap-provider`: First-class Cap Standalone (trycap) captcha provider: instance URL, widget endpoint, JSON siteverify, default template branch.

### Modified Capabilities

None.

## Impact

- `pkg/configuration` — `trycap` enum, `CaptchaTrycapInstanceUrl`, validation.
- `pkg/captcha` — provider row, JSON verify, template data, tests.
- `pkg/bouncer` — pass instance URL into captcha `New`.
- `captcha.html`, README, `examples/trycap-captcha`.
