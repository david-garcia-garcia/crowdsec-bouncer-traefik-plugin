## 1. Sync dest

- [ ] 1.1 Merge `origin/master` into this branch. If dest then threads a client address into `Validate`, absorb `remoteip` on both encodings when non-empty. If dest is still `Validate(r)` only, do not invent the argument

## 2. Config

- [ ] 2.1 Add `CaptchaCustomValidateBody` / `captchaCustomValidateBody` on Config, default `""`
- [ ] 2.2 In `validateCaptcha`, after trim accept only `""`, `form`, `json`. Reject unknown tokens for any provider with `CaptchaCustomValidateBody: must be empty, form, or json`. Reject `json` when provider is not `custom` with `CaptchaCustomValidateBody: json is only valid when CaptchaProvider is custom`. Built-in `""` / `form` stay ignored

## 3. Siteverify request

- [ ] 3.1 Store the encoding on `Client` (sibling of `challengeURL`). `bouncer.New` passes `CaptchaCustomValidateBody` into `Client.New`. Do not put it on `infoProviders`
- [ ] 3.2 Custom + `json`: POST `application/json` `secret`+`response` via dest `httpClient`. Custom + `form`/omit and all built-ins: keep `PostForm`
- [ ] 3.3 Include `remoteip` on both encodings only when task 1.1 absorbed a non-empty address. Do not re-parse forwarded headers. Keep dest reply `mime.ParseMediaType` + `success`, gate cookie + 302, void `cache.Set`

## 4. Tests

- [ ] 4.1 Grow `Test_ValidateParams` / captcha settings tests: custom+`json`/`form`/omit pass; built-in+`json` fails; `JSON`/`Form`/other tokens fail; built-in+`form`/omit pass; whitespace-padded ` json ` on custom passes
- [ ] 4.2 Captcha `zzz_` tests: custom+`json` sees JSON Content-Type and `secret`/`response` (plus `remoteip` only if task 1.1 absorbed it); custom+`form`/omit still urlencoded; built-in still urlencoded; custom+`json` success still 302 + `crowdsec_captcha_gate`
- [ ] 4.3 Update every `Client.New` test helper for the new argument

## 5. Docs

- [ ] 5.1 README: document `CaptchaCustomValidateBody` (lowercase `form`/`json`, custom-only `json`) and a CapJS custom example (validate URL + `cap-token` + `json`). Do not add `trycap` or retarget `examples/custom-captcha`

## 6. Verify

- [ ] 6.1 `go test ./pkg/configuration/ ./pkg/captcha/ ./pkg/bouncer/` and `golangci-lint run ./pkg/configuration/... ./pkg/captcha/... ./pkg/bouncer/...`
