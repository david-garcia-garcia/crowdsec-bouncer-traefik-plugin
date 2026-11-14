## 1. AppSec verdict handling

- [ ] 1.1 `handleCaptchaKindServeHTTP` takes the header reason and the downgrade ban reason from its caller; `handleRemediationServeHTTP` passes `headerReasonFromOrigin(origin)` and `ReasonLAPI` (no change for existing callers)
- [ ] 1.2 Add `serveAppsecCaptchaGate` (origin `appsec`, header reason `appsec`, ban reason `APPSEC`)
- [ ] 1.3 `applyAppsecServeHTTP`: `captcha` → return false when a captcha rule matched, else `serveAppsecCaptchaGate`
- [ ] 1.4 `applyAppsecServeHTTP`: action other than allow/ban/captcha/challenge with empty `user_body_content` → ban with new closed reason `appsec-action-empty`
- [ ] 1.5 `serveAppSec`: when `applyAppsecServeHTTP` did not write, a challenge-marker POST on a router with a usable captcha client → `serveAppsecCaptchaGate`
- [ ] 1.6 `formatAppsecRelayHeader` no longer needs a `captcha` case once `captcha` never reaches relay

## 2. Tests

- [ ] 2.1 Replace `TestHandleNextServeHTTPRelaysStructuredAppsecCaptcha` / `TestHandleNextServeHTTPEmptyCaptchaBodyRelaysStatus` with captcha-gate tests: challenge page + `captcha:appsec` + dropped origin `appsec`; valid gate cookie reaches next; unsubscribed → `ban:captcha-downgrade`; captcha rule → `captcha:rules`
- [ ] 2.2 Bodyless unknown action → ban page + `ban:appsec-action-empty`; bodied unknown action still relays
- [ ] 2.3 Challenge-marker POST allowed by AppSec: valid token → 302 + gate cookie, backend not called; valid gate cookie → 302 solved; no marker → backend gets the body; router without captcha → backend
- [ ] 2.4 Mock e2e: AppSec stand-in returns `{"action":"captcha","http_status":403}` for a probe URI (GET only) and a scenario that solves it through the form POST

## 3. Docs

- [ ] 3.1 README: header table (`captcha:appsec`, `ban:appsec-action-empty`) and AppSec section (captcha verdict uses the router captcha)
- [ ] 3.2 `knowledge/devdocs/core_plugin_appsec.md` and `knowledge/devdocs/core_plugin_middleware_captcha-routing.md`

## 4. Verify

- [ ] 4.1 `go test ./pkg/bouncer/ ./pkg/appsec/ -count=1`
- [ ] 4.2 `go test ./... -count=1`, `golangci-lint run`, yaegi test as CI runs it
