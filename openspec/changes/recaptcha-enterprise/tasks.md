## 1. Config knobs and ValidateParams

- [ ] 1.1 Add `recaptcha-enterprise` to the provider allowlist in `validateCaptcha` (`pkg/configuration/configuration.go`)
- [ ] 1.2 Add `CaptchaEnterpriseKeyType`, `CaptchaEnterpriseProjectId`, `CaptchaEnterpriseApiKey` / `CaptchaEnterpriseApiKeyFile`, `CaptchaEnterpriseAction`, `CaptchaEnterpriseMinScore` (string) on Config with `captchaEnterprise*` JSON tags, next to the other `captcha*` stems
- [ ] 1.3 When provider is `recaptcha-enterprise`, require key type `checkbox` or `score`, non-empty project id, and non-empty API key via `GetVariable`. Ignore those knobs for other providers
- [ ] 1.4 Score requires non-empty action and a parsed min score `> 0` and `<= 1`. Checkbox may omit both. Reject zero, negative, `1.1`, and non-numeric min score
- [ ] 1.5 Skip the empty-`CaptchaSecretKey` reject only when the provider is `recaptcha-enterprise`. Site key and gate secret stay required

## 2. Widget, verifier, and Validate outcomes

- [ ] 2.1 Add Widget (script URL, class, token field, action, boot script, retry-after-reject) and Verifier `Pass(token, remoteIP) (bool, error)` on the Client. `New` is the only provider/key-type switch. Do not grow `New`'s positional list; pass enterprise knobs as a named construction value
- [ ] 2.2 Move today's `postSiteverify` / `success` decode into the siteverify verifier. Keep form-versus-JSON, `remoteip` only when the address is non-empty, and Content-Type miss as Pass-false with no error
- [ ] 2.3 Change `Validate` to `(Outcome, error)` with `None`, `Pass`, `Reject`. Empty token is `None` and MUST NOT call the verifier. Error is the error return. Update `ServeHTTP` (the only production caller) and `pkg/captcha/zzz_validate_body_test.go`

## 3. Assessments verifier

- [ ] 3.1 POST JSON to `https://recaptchaenterprise.googleapis.com/v1/projects/{project}/assessments` on the existing captcha `http.Client` and timeout. Header `X-Goog-Api-Key`. Do not put the key in the query string. Do not log the key. No Google client library
- [ ] 3.2 Body: `event.token`, `event.siteKey`, `event.userIpAddress` only when `remoteIP` is non-empty, `event.expectedAction` only when action is configured. Reuse the `remoteIP` already passed in. Do not parse forwarded headers
- [ ] 3.3 Pass order: `tokenProperties.valid`, then action case-insensitively when configured, then `riskAnalysis.score` when a minimum is set. Non-2xx, missing/non-JSON body, or a Google error envelope without `tokenProperties` is Error. `valid` false is Reject

## 4. ServeHTTP, template, and ownership

- [ ] 4.1 Pair enterprise checkbox (`enterprise.js`, `g-recaptcha`, retry) and score (`enterprise.js?render={siteKey}`, no class, no retry, fixed `ready`/`execute` boot). Field name stays `g-recaptcha-response`
- [ ] 4.2 ServeHTTP: Pass mints the gate and 302s. None or Error renders with boot. Reject + retry renders with boot. Reject + no-retry omits boot
- [ ] 4.3 Stock `captcha.html` stays one file. Template map gains `BootScript`, `Action`, `DrawCheckbox` (non-empty when the checkbox div should render). Keep `SiteKey`, `FrontendJS`, `FrontendKey`, `ChallengeURL`
- [ ] 4.4 Add the enterprise knobs to `ownership` in `pkg/captcha/session.go` so a change reclaims the client. `newOwnerClient` passes the named construction value into `New`

## 5. Tests

- [ ] 5.1 Configuration `zzz_`: allowlist accepts `recaptcha-enterprise`; unknown provider still fails; enterprise required knobs; score action/min-score rules; checkbox omit; empty secret passes only for enterprise; hCaptcha/classic/Turnstile/custom still require secret
- [ ] 5.2 Captcha `zzz_`: assessments URL, header (not query), event fields, `remoteIP` omitempty, pass order, Error vs Reject, case-insensitive action. Score reject omits boot. Checkbox reject keeps boot. Pass still sets `crowdsec_captcha_gate` and 302
- [ ] 5.3 Siteverify tests still cover form/JSON, `remoteip`, Content-Type miss as Pass-false, and `success`. Update every `Client.New` / `Validate` helper for the new construction value and Outcome

## 6. Docs

- [ ] 6.1 README: add `recaptcha-enterprise` next to the other validator tokens. Document the enterprise knobs (`checkbox`/`score`, project id, API key / file, action, min score string). Say `captchaSecretKey` is unused for this provider. Keep classic `recaptcha` as `api.js` / siteverify

## 7. Verify

- [ ] 7.1 `go test ./pkg/configuration/ ./pkg/captcha/ ./pkg/bouncer/` and `golangci-lint run ./pkg/configuration/... ./pkg/captcha/... ./pkg/bouncer/...`
