## Why

After a visitor has a valid `crowdsec_captcha_gate` cookie, leftover-form detection still treats a non-empty vendor token field (`g-recaptcha-response` and the rest) as a CrowdSec challenge POST. An application form that embeds the same widget is then `302 Found` and never reaches origin.

## What Changes

- After `Check` is true, `IsCaptchaFormPost` identifies a leftover CrowdSec challenge only when the POST carries `crowdsec_captcha_challenge=v1`. It MUST NOT treat `widget.TokenField` as leftover proof.
- First-solve is unchanged: when `Check` is false, `Validate` still reads `TokenField`.
- Keep `captchaFormMaxBytes` (64KiB) and the same urlencoded / multipart / already-parsed peek. Look up the marker instead of `TokenField`.
- `pkg/captcha` owns the leftover-detection name and value constants. Shipped challenge templates emit that same hidden input. Do not share `gatePayloadVersion`. Do not add a Config key.
- A replaced template that omits the hidden input still solves on the first submit. A second submit of that template is forwarded. No `TokenField` fallback.
- The `handleCaptchaKindServeHTTP` sequence stays: custom-resource → `Check` then leftover-form 302 → other Check-true continue → else `ServeHTTP`.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `core_plugin_middleware_captcha-routing`: Check-true leftover-form POST is `crowdsec_captcha_challenge=v1`, not the provider token field. Detection still MUST NOT share the first-verify reader and still MUST NOT cost origin its body.
- `core_plugin_middleware_captcha-widget`: shipped challenge HTML emits the leftover-form marker owned by leftover detection. First-solve still reads `TokenField`.

## Impact

- `pkg/captcha` (`IsCaptchaFormPost` field lookup, leftover-marker constants, `pkg/captcha/zzz_routing_test.go`)
- `pkg/bouncer` (`handleCaptchaKindServeHTTP` caller stays; `pkg/bouncer/zzz_captcha_routing_test.go`)
- Shipped templates: `captcha.html`, `examples/captcha/captcha.html`, `examples/custom-captcha/captcha.html`, `tests/e2e/real/config/captcha-dummy.html`, `tests/e2e/mock/scenarios/captcha/captcha.html`, `tests/e2e/mock/scenarios/captcha-ban-origins/captcha.html`
- Stay out of `pkg/captcha/gate.go` cookie format, `Validate` / `readFieldFromRequest`, Config, and vendor `TokenField` names
