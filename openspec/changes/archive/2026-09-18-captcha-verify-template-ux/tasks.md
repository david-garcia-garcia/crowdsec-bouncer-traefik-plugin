## 1. Siteverify remoteip

- [x] 1.1 Change `Validate` to `Validate(r, remoteIP)` and `body.Add("remoteip", remoteIP)` with `secret` and `response`. Call it from `ServeHTTP` with the existing `remoteIP` argument. Do not parse forwarded headers in captcha.
- [x] 1.2 Add a `zzz_` test under `pkg/captcha/` that stubs siteverify, captures the POST form, and asserts `remoteip` equals the `remoteIP` passed to `ServeHTTP`.

## 2. Transport and decode 200

- [x] 2.1 In `ServeHTTP`, when `Validate` returns `err != nil`, log and fall through to the existing 200 challenge render. Do not write `StatusBadRequest`. Keep `(false, err)` from `PostForm` and JSON `Decode`. Keep `(false, nil)` for empty token, `success:false`, and non-JSON Content-Type.
- [x] 2.2 Add `zzz_` cases: provider `PostForm` failure and JSON Content-Type with a non-JSON body. Assert HTTP 200, captcha HTML, no `crowdsec_captcha_gate`. Keep the existing mixed-case JSON success cookie+302 case.

## 3. Loadable captcha template

- [x] 3.1 In `validateEnabledCaptchaSettings`, remove the empty-`CaptchaFilePath` early return. When provider is set, reject `""` with `CaptchaFilePath: cannot be empty when CaptchaProvider is set`, then `GetTemplate`. Ban path stays "when path is set".
- [x] 3.2 In `Client.New`, return the `GetTemplate` error instead of discarding it (`_`). Do not add `cacheClient`.
- [x] 3.3 Give configuration and plugin tests that blank `CaptchaFilePath` to skip `GetTemplate` a temp readable `captcha.html` (same pattern as `pkg/captcha/zzz_servehttp_test.go`). Empty site/secret cases still fail on the key error.
- [x] 3.4 Grow `Test_ValidateParams` / `validateEnabledCaptchaSettings`: provider + empty path; provider + missing file; empty ban path still accepted; alone + empty captcha path. Add `Client.New` error case and `TestNew_*` empty captcha path → nil handler, no LAPI Open.
- [x] 3.5 Delete `knowledge/debt/2026-09-18-captcha-nil-template-panic.md` and close that `issues.md` row if present.

## 4. Verify

- [x] 4.1 `go test ./pkg/captcha ./pkg/configuration ./` and `golangci-lint run ./pkg/captcha/... ./pkg/configuration/... .`
