## 1. Config

- [x] 1.1 Add `TrycapProvider = "trycap"` and `CaptchaTrycapInstanceUrl` (`json:"captchaTrycapInstanceUrl,omitempty"`)
- [x] 1.2 `validateCaptcha`: allow `trycap`; require non-empty http/https `captchaTrycapInstanceUrl`; do not require `CaptchaCustom*` for trycap
- [x] 1.3 Unit tests for valid trycap config and missing instance URL

## 2. Captcha client

- [x] 2.1 Register trycap `infoProvider`: pinned jsDelivr `cap-widget` URL, response `cap-token`, JSON verify flag; join instance + site key for API endpoint and siteverify URL in `New`
- [x] 2.2 Pass `config.CaptchaTrycapInstanceUrl` from `bouncer.New` into captcha `New`
- [x] 2.3 `Validate`: JSON POST `{"secret","response"}` with `Content-Type: application/json` when the provider is JSON; keep `PostForm` for other providers
- [x] 2.4 `ServeHTTP` template map includes `CapApiEndpoint` (empty for SaaS)

## 3. Template and docs

- [x] 3.1 Default `captcha.html`: Cap widget + module script when `CapApiEndpoint` is set; existing class widget otherwise; auto-submit on `solve`
- [x] 3.2 README: document `trycap` and `captchaTrycapInstanceUrl`
- [x] 3.3 `examples/trycap-captcha` labels (no Cap Docker stack required)

## 4. Tests

- [x] 4.1 httptest: JSON body and Content-Type on success; no siteverify when `cap-token` missing
- [x] 4.2 httptest: constructed siteverify path includes site key
- [x] 4.3 Existing hcaptcha/custom PostForm behavior unchanged (assert if a test already covers it; otherwise a sibling test)
