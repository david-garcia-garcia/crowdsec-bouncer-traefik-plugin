## 1. Configuration

- [x] 1.1 Add `CaptchaGateSecret`, `CaptchaGateSecretFile`, `CaptchaGateBindIP` (default true) with validation when captcha enabled
- [x] 1.2 Resolve gate secret via existing `GetVariable` pattern

## 2. Captcha gate cookie

- [x] 2.1 Implement mint/validate in `pkg/captcha/gate.go` (v1 payload, base64url HMAC, skew, hmac.Equal)
- [x] 2.2 `ServeHTTP` sets cookie on valid solve then 302; remove cache Set
- [x] 2.3 `Check(r, remoteIP)` validates cookie only; drop `CaptchaDoneValue` and cache client from `New`

## 3. Bouncer wiring

- [x] 3.1 Stop passing `lapiClient.Cache()` into captcha `New`
- [x] 3.2 Update remediation path to `Check(r, req.remoteIP)`

## 4. Tests

- [x] 4.1 Unit tests for gate mint/validate (bind IP, cookie-only, expiry, tamper)
- [x] 4.2 Update existing captcha/bouncer tests off cache grace

## 5. Verify

- [x] 5.1 `go test ./pkg/captcha/ ./pkg/bouncer/ ./pkg/configuration/`
