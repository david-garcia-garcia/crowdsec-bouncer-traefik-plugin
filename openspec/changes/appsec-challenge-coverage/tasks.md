## 1. Empty-challenge ban page

- [ ] 1.1 In `pkg/bouncer/zzz_bouncer_test.go`, next to `TestHandleNextServeHTTPEmptyChallengeBodyBans`, add a test (comment cites https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/397) with a non-nil `banTemplate` for missing `user_body_content` (`{"action":"challenge","http_status":200}`) and explicit empty-string `user_body_content`.
- [ ] 1.2 Assert HTTP 403, `X-Remediation: ban`, and the rendered operator ban page (not HTTP 200 with an empty body). Reuse `testBouncerWithAppsec` and `testClientRequest`. Do not invent a second client address.

## 2. CSP replace and separate Set-Cookie

- [ ] 2.1 In the same file, next to `TestHandleNextServeHTTPRelaysStructuredAppsecChallenge`, add a test that `Header().Set("Content-Security-Policy", ...)` on `httptest.ResponseRecorder` before `handleNextServeHTTP`, then AppSec returns a different CSP plus two `user_cookies`.
- [ ] 2.2 Assert `Header().Values("Content-Security-Policy")` has exactly one value equal to the AppSec header, and `Header().Values("Set-Cookie")` has both cookie strings as separate values.

## 3. Run and bound production

- [ ] 3.1 Run `go test ./pkg/bouncer/ -count=1` (or the new test names). Do not edit `pkg/bouncer/bouncer.go` unless a new test fails.
- [ ] 3.2 Confirm the folded delta on `core_plugin_appsec_bot-detection` still names CSP replace and separate `Set-Cookie`; empty-challenge ban stays the existing scenario.

