## 1. Config allowlist

- [ ] 1.1 Add `EucaptchaProvider = "eucaptcha"` next to the other provider constants in `pkg/configuration/configuration.go`
- [ ] 1.2 Accept `eucaptcha` on the `validateCaptcha` allowlist without dropping `recaptcha-enterprise`. Update the allowlist error string
- [ ] 1.3 Keep `CaptchaSecretKey` required for `eucaptcha` (not the enterprise empty-secret exception)

## 2. Pass arity and New pairing

- [ ] 2.1 Widen `Verifier.Pass` to `Pass(token, remoteIP, userAgent string) (bool, error)` in `pkg/captcha/verifier.go`. Update `siteverifyVerifier` and `assessmentsVerifier` to take `userAgent` and ignore it
- [ ] 2.2 `Validate` SHALL call `Pass(token, remoteIP, r.UserAgent())`. Empty token stays `None` (no `Pass` call). Do not put User-Agent on `clientRequest`
- [ ] 2.3 Add a `New` case for `configuration.EucaptchaProvider` beside `recaptcha-enterprise`. Store Widget `{ScriptURL: https://cdn.eu-captcha.eu/verify.js, Class: eu-captcha, TokenField: eu-captcha-response, RetryAfterReject: true}` and the eucaptcha verifier. Do not add `eucaptcha` to `infoProviders`. Do not grow `New`'s positional list. Do not change `captcha.html`

## 3. Eucaptcha verifier

- [ ] 3.1 Add `pkg/captcha/eucaptcha.go` (`eucaptchaVerifier`). POST JSON to `https://api.eu-captcha.eu/v1/verify` on the existing captcha `http.Client` and timeout. `Content-Type: application/json`. Do not log the secret
- [ ] 3.2 Body fields: `sitekey`, `secret`, `client_ip` (the `remoteIP` already passed in), `client_token`, `client_user_agent`. Reuse `GetRemoteIP` / `clientRequest.remoteIP`. Reuse `r.UserAgent()`. Do not parse `X-Forwarded-For`, `X-Real-Ip`, `X-Client-IP`, or `RemoteAddr`. Do not send the LAPI plugin User-Agent
- [ ] 3.3 Empty `remoteIP` is Pass-false with no vendor POST. Empty `userAgent` is still POSTed as `""`
- [ ] 3.4 HTTP 200 JSON: Pass-true only when `success` is true and `train` is JSON false or null (`*bool` nil counts as false-or-null). `train` true is Pass-false. `success` false is Pass-false. Non-2xx or undecodable JSON is the error return. Cap the body the same way assessments does. No `/verify-credentials` probe

## 4. Tests

- [ ] 4.1 Configuration `zzz_`: allowlist accepts `eucaptcha`; `recaptcha-enterprise` still accepted; unknown provider still fails; empty secret fails for `eucaptcha`; empty secret still passes only for `recaptcha-enterprise`; leftover enterprise knobs on `eucaptcha` are ignored
- [ ] 4.2 Captcha `zzz_eucaptcha_test.go`: verify URL and JSON fields; `remoteIP` reuse; empty address does not POST; empty User-Agent is sent; `success`/`train` matrix; non-2xx and undecodable JSON are error; Pass still sets `crowdsec_captcha_gate` and 302; `train` true does not mint the cookie; empty token is `None` and does not POST
- [ ] 4.3 Update every `Pass(` implementer and test helper for the new arity. Siteverify tests still cover form/JSON, `remoteip` omit-when-empty, and `success`

## 5. Docs

- [ ] 5.1 README: add `eucaptcha` to the captcha providers list and to `CaptchaProvider` expected values. Say site key and secret are required. Keep `recaptcha-enterprise`. Do not document a `/verify-credentials` probe

## 6. Verify

- [ ] 6.1 `go test ./pkg/configuration/ ./pkg/captcha/ ./pkg/bouncer/` and `golangci-lint run ./pkg/configuration/... ./pkg/captcha/... ./pkg/bouncer/...`
