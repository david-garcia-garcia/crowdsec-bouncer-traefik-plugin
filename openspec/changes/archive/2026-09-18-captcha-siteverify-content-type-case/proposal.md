## Why

`Client.Validate` treats a provider siteverify response as JSON only when `Content-Type` has the lowercase prefix `application/json`. A provider that returns `Application/JSON` plus `{"success":true}` is logged as `responseType:noJson` and yields `(false, nil)`, so `ServeHTTP` writes the 200 challenge and never mints `crowdsec_captcha_gate`. RFC 9110 § 8.3.1 says type/subtype tokens are case-insensitive and the match is the type token before parameters.

## What Changes

- Treat siteverify as JSON when the media type before parameters equals `application/json` case-insensitively.
- `success:true` on that path keeps today's gate cookie plus 302 (same as lowercase `application/json`).
- Add one `pkg/captcha/` `zzz_` regression for `Application/JSON` + `{"success":true}`.
- This defect only. Not GitHub #52. Not inbound form `Content-Type`. Not cookie format, provider URLs, keys, or the siteverify request body.

## Capabilities

### New Capabilities

- `core_plugin_middleware_captcha-siteverify`: how `Client.Validate` classifies a provider siteverify response as JSON and returns success.

### Modified Capabilities

None.

## Impact

- `pkg/captcha/captcha.go` (`Validate` Content-Type check)
- captcha unit tests under `pkg/captcha/` (one `zzz_` regression)
- No public config, no other packages
