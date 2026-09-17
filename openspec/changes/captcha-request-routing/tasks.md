## 1. Configuration

- [x] 1.1 Add optional `CaptchaCustomChallengeURL` (`json:"captchaCustomChallengeUrl,omitempty"`) on `configuration.Config` and `CreateConfig` default empty
- [x] 1.2 Keep `validateCaptcha` required set as the existing four custom fields; empty challenge URL MUST pass

## 2. Captcha owners

- [x] 2.1 Pass challenge URL into `captcha.Client.New`; parse JsURL + optional challenge URL once; store exact paths that are non-empty and start with `/` (custom provider only)
- [x] 2.2 Add `IsCustomResourceRequest` (exact `req.URL.Path` match; never `CaptchaCustomValidateURL`)
- [x] 2.3 Add `IsCaptchaFormPost` (POST + non-empty `captchaResponseFromRequest` for `infoProvider.response`); do not add a second body reader
- [x] 2.4 Add `WriteSolvedRedirect` (`302` to `req.URL.String()`, `solved-captcha` header when configured; do not remint cookie or call the provider)

## 3. Bouncer routing

- [x] 3.1 Rewrite `handleRemediationServeHTTP` captcha branch: drop `Method != HEAD`; order custom-resource → Check+form POST 302 → Check origin → `ServeHTTP`; else ban
- [x] 3.2 Passthrough and Check-true ordinary requests MUST call `handleNextServeHTTP`; ban MUST NOT passthrough
- [x] 3.3 Wire `Check(req.Request, req.remoteIP)` only; no cache grace keys; do not touch `pkg/lapi` or `pkg/reclaim`

## 4. Tests

- [x] 4.1 Check-true captcha-form POST → 302 same URL, origin not called; ordinary POST without response field → origin
- [x] 4.2 Custom JS path and optional challenge path under captcha → origin; same path under ban → ban; prefix / ValidateURL path MUST NOT pass
- [x] 4.3 HEAD + captcha (non-resource) → captcha path, not ban; replace `TestCaptchaMethodBasedLogic`

## 5. Verify

- [x] 5.1 `go test ./pkg/captcha/ ./pkg/bouncer/ ./pkg/configuration/`
- [ ] 5.2 PR body cites #48 and #50
