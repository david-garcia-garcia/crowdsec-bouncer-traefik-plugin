## 1. Leaf inbound request

- [x] 1.1 Add `pkg/clientrequest` with exported type `Request` embedding the live `*http.Request`. Constructor `New` takes that request plus GetRemoteIP `remoteIP` and `ipAddr`. `New` sets the family with `ip.FamilyOfIP`. Unexported scheme with a getter. Callers MUST NOT assign scheme. Package MUST NOT import bouncer, captcha, or appsec
- [x] 1.2 Implement the scheme rule in `New` only: trimmed `X-Forwarded-Proto` whole-value EqualFold `http` or `https` wins (store `http`/`https`); else TLS non-nil → `https`, else `http`. Do not comma-split. Do not treat `wss`, empty, `https,http`, `Forwarded`, `Front-End-Https`, `X-Forwarded-Protocol`, `X-Scheme`, or `URL.Scheme` as a set proto. Do not re-check hop trust. Do not write scheme onto the live `*http.Request`
- [x] 1.3 Add `AbsoluteURL`: constructor scheme, `URL.Host` when non-empty else `Request.Host`, path and query preserved. Do not use `URL.Scheme`
- [x] 1.4 Add `pkg/clientrequest/zzz_request_test.go` for the scheme matrix (forwarded https/http with case and trim, proto `http`+TLS, TLS fallback for wss/empty/absent/`https,http`, `URL.Scheme` ignored) and AbsoluteURL origin-form plus `URL.Host` wins. Assert `URL.Scheme` on the live request is unchanged

## 2. Bouncer wiring

- [x] 2.1 Delete `pkg/bouncer/clientrequest.go`. In `ServeHTTP`, after `GetRemoteIP`, call `clientrequest.New`. `New` stores `ipAddr.String()` when the address parsed, and keeps the raw extract when it did not. Call sites keep the name `req`
- [x] 2.2 Point every production bouncer handler that took `clientRequest` at `clientrequest.Request`. Pass `req` into captcha `ServeHTTP`/`Check`/`Validate` and AppSec `Query` (no parallel `remoteIP` string, no `req.Request` plus IP)
- [x] 2.3 Update `testClientRequest` and every `pkg/bouncer/zzz_*.go` builder to `clientrequest.New` (or a thin helper around it)

## 3. Captcha consumes scheme

- [x] 3.1 Change `ServeHTTP`, `Check`, `Validate`, and `setGateCookie` to take `clientrequest.Request`. `setGateCookie` sets Secure iff scheme is `https`. MUST NOT read `X-Forwarded-Proto` or `Request.TLS`. Leave `IsCustomResourceRequest`, `IsCaptchaFormPost`, `WriteSolvedRedirect`, `gateCookieValue`, and `RequestDomain` on `*http.Request` / host string
- [x] 3.2 Rewrite `pkg/captcha/zzz_gate_test.go` Secure tests to go through `New` then `setGateCookie`. Keep forwarded-https and TLS-without-set-proto as constructor+cookie coverage. Add proto `http` plus TLS → not Secure. `Test_setGateCookie_connectionTLSSetsSecure` MUST NOT set proto `http`. Update Check/Validate/ServeHTTP tests that passed a bare request plus IP string

## 4. AppSec consumes absolute URL

- [x] 4.1 Change `Query` (and `newAppsecForwardRequest`) to take `clientrequest.Request`. Set `X-Crowdsec-Appsec-Uri` from `AbsoluteURL()`. Set `X-Crowdsec-Appsec-Ip` from that value's remoteIP. Leave `X-Crowdsec-Appsec-Host` as `Request.Host`. MUST NOT use `URL.String()` or `URL.Scheme` for the URI. MUST NOT derive scheme from proto or TLS
- [x] 4.2 Update every `Query(` in `pkg/appsec/zzz_*.go` to pass `clientrequest.New`. Assert `X-Crowdsec-Appsec-Uri` is absolute with constructor scheme on at least one origin-form request (`URL.Host` empty, `Request.Host` set)

## 5. Dual-cookie httptest

- [x] 5.1 Add one `pkg/bouncer/zzz_*_test.go` that drives the plugin with forged TLS on/off and `X-Forwarded-Proto`. Stub AppSec sets `__crowdsec_challenge` Secure iff the forwarded URI scheme is `https`. Assert `crowdsec_captcha_gate` Secure and `__crowdsec_challenge` Secure for https proto / TLS fallback, and both omit Secure for proto `http`. Do not teach mocklapi CrowdSec's scheme check
- [x] 5.2 Real-stack Pester on the existing HTTP entrypoint. The published-port peer stays inside `forwardedHeaders.trustedIPs`, so Traefik keeps `X-Forwarded-Proto`. Assert both cookies Secure for proto `https` and both omit Secure for proto `http`. CrowdSec mints `__crowdsec_challenge` via `GrantChallengeCookie` on `/origin-scheme`. No HTTPS entrypoint

## 6. Usage packets

- [x] 6.1 Update `knowledge/devdocs/core_plugin_middleware_captcha-gate.md`: Secure iff inbound-request scheme is `https`; captcha MUST NOT read proto or TLS; do not copy GetRemoteIP hop trust
- [x] 6.2 Update `knowledge/devdocs/core_plugin_appsec.md` pattern snippet and Query wiring: take `clientrequest.Request`; URI is AbsoluteURL; still do not parse `__crowdsec_challenge`
- [x] 6.3 Update `knowledge/devdocs/core_plugin_ip.md` Language for `clientRequest`: cluster now includes constructor scheme; still avoid a fourth address field; key file is `pkg/clientrequest`

## 7. Verify

- [x] 7.1 `go test ./pkg/clientrequest/ ./pkg/captcha/ ./pkg/appsec/ ./pkg/bouncer/` and `golangci-lint run ./pkg/clientrequest/... ./pkg/captcha/... ./pkg/appsec/... ./pkg/bouncer/...`
