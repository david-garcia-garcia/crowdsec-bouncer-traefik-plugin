## 1. Leftover-form detection

- [x] 1.1 Add `leftoverFormMarkerName` (`crowdsec_captcha_challenge`) and `leftoverFormMarkerValue` (`v1`) in `pkg/captcha`; do not read `gatePayloadVersion`; do not add a Config key
- [x] 1.2 Change `IsCaptchaFormPost` to answer yes only when that marker equals `v1`; drop the `TokenField == ""` early return; keep the `Client` method and the bouncer call `Check(req)` then `IsCaptchaFormPost(req.Request)`
- [x] 1.3 Keep `peekCaptchaFormBody` / `formFieldValue` and `captchaFormMaxBytes` (64KiB); retarget the cap comment from provider token to leftover-form marker; do not share a helper with `readFieldFromRequest`

## 2. Shipped challenge pages

- [x] 2.1 Add `<input type="hidden" name="crowdsec_captcha_challenge" value="v1">` inside the POST form on bundled `captcha.html`
- [x] 2.2 Add the same hidden input on `examples/captcha/captcha.html` and `examples/custom-captcha/captcha.html`
- [x] 2.3 Add the same hidden input on `tests/e2e/real/config/captcha-dummy.html`, `tests/e2e/mock/scenarios/captcha/captcha.html`, and `tests/e2e/mock/scenarios/captcha-ban-origins/captcha.html`
- [x] 2.4 Assert each of those six pages contains `leftoverFormMarkerName` and `leftoverFormMarkerValue`

## 3. Routing tests

- [x] 3.1 Point `pkg/captcha/zzz_routing_test.go` leftover cases at the marker (urlencoded, multipart, already-parsed, over-cap, unknown content length) instead of `TokenField`
- [x] 3.2 Cover TokenField-without-marker is not a leftover form, marker-without-TokenField is, and a non-`v1` marker value is not
- [x] 3.3 Point `TestHandleRemediationServeHTTP_solvedFormPostRedirects` at a Check-true POST that carries the marker; keep origin-not-called and no cookie remint
- [x] 3.4 Add a Check-true POST with a non-empty provider field and no marker that reaches origin with its body unchanged
- [x] 3.5 Point the over-max bouncer body test at a payload that contains the marker name and still reaches origin intact
- [x] 3.6 Keep first-solve `Validate` / `readFieldFromRequest(TokenField)` tests green without requiring the leftover marker

## 4. Verify

- [x] 4.1 `go test ./pkg/captcha/ ./pkg/bouncer/ -count=1`
- [x] 4.2 `go test ./pkg/... -count=1` and `go test . -count=1`
