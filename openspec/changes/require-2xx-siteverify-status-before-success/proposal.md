## Why

On DestBranch, `Validate` accepts a received siteverify body when `Content-Type` starts with `application/json` and decoded `success` is true, and never reads `res.StatusCode`. HTTP 500 plus `{"success":true}` therefore mints `crowdsec_captcha_gate` and 302s. A provider error that happens to look like a solve must not grant grace.

## What Changes

- Require a 2xx siteverify status before Content-Type matching or decoding `success`.
- Any other received status is a failed verify: `(false, nil)` — no `crowdsec_captcha_gate`, no solved 302. `ServeHTTP` re-renders the challenge at 200.
- Add a `pkg/captcha/` `zzz_*_test.go` regression: HTTP 500 + JSON `{"success":true}` must not set the gate cookie or 302.
- New spec owns siteverify HTTP acceptance. Gate cookie format and first-solve 302 after a real success stay on `core_plugin_middleware_captcha-gate`.
- Not **BREAKING** for config keys. A deployment whose siteverify already answers non-2xx with JSON `success: true` will stop granting grace (intentional).

## Capabilities

### New Capabilities

- `core_plugin_middleware_captcha-siteverify`: When a siteverify response is received, require status 200–299 before reading `success`. Non-2xx is a failed verify.

### Modified Capabilities

None. `core_plugin_middleware_captcha-gate` still mints the cookie after successful provider verify; this change defines that success. `core_plugin_middleware_captcha-routing` is unchanged.

## Impact

- `pkg/captcha/captcha.go` (`Validate`; `ServeHTTP` only as the mint/302 caller)
- Captcha unit tests under `pkg/captcha/`
- Out of scope: `PostForm` transport errors (PR #28), Content-Type matching, gate cookie format, captcha routing, body drain, `remoteip` on the siteverify POST
