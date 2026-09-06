## 1. Captcha helpers

- [x] 1.1 Extract the existing solved-captcha HTTP response (remediation header `solved-captcha` when configured, `StatusFound` to the request URL) onto `captcha.Client` and use it from `ServeHTTP` after a successful verify
- [x] 1.2 Add a `captcha.Client` method that reports whether a request is a POST carrying the configured provider response field (hcaptcha, recaptcha, turnstile, custom)
- [x] 1.3 When that method reads a POST body and the field is absent, restore `Body` so a later handler can read it

## 2. Bouncer grace path

- [x] 2.1 In `handleRemediationServeHTTP`, when captcha is valid, remediation is captcha, and `Check(req.remoteIP)` is true, intercept captcha form POSTs with the solved redirect instead of `handleNextServeHTTP`
- [x] 2.2 Leave GET and POSTs without the provider field on `handleNextServeHTTP`; do not re-parse `RemoteAddr` for the grace key

## 3. Tests

- [x] 3.1 Captcha helper tests: built-in hcaptcha field, custom field, GET false, POST without field false, body restored when not a captcha form POST
- [x] 3.2 Bouncer tests: after grace, captcha form POST returns 302 and does not call next; ordinary POST calls next with the original body; GET during grace still calls next
- [x] 3.3 `go test ./pkg/captcha/ ./pkg/bouncer/`
