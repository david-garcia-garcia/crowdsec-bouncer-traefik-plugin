## 1. setGateCookie Secure

- [ ] 1.1 In `pkg/captcha/gate.go` `setGateCookie`, set `Secure` when `r.TLS != nil` or trimmed `Header.Get("X-Forwarded-Proto")` EqualFold `https` on the whole value
- [ ] 1.2 Do not add hop-trust fields to `captcha.Client`, do not change `New`, do not call `GetRemoteIP` for scheme

## 2. Tests

- [ ] 2.1 Add `Test_setGateCookie_forwardedHTTPSSetsSecure` (`TLS == nil`, proto `https` / `HTTPS` / padded)
- [ ] 2.2 Add `Test_setGateCookie_connectionTLSSetsSecure`
- [ ] 2.3 Add `Test_setGateCookie_httpOrAbsentProtoOmitsSecure` (proto `http`, `wss`, absent, empty; `TLS == nil`)
- [ ] 2.4 Do not add `TestHunt_*`

## 3. Specs

- [ ] 3.1 Apply the Secure clause on `openspec/specs/core_plugin_middleware_captcha-gate/spec.md` from this change's delta

## 4. Verify

- [ ] 4.1 `go test ./pkg/captcha/`
- [ ] 4.2 `go vet ./pkg/captcha/`
