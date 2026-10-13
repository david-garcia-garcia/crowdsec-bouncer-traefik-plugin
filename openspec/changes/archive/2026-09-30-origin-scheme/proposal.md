## Why

Captcha gate `Secure` is decided inside `setGateCookie` from `Request.TLS` **or** proto `https`, while AppSec `X-Crowdsec-Appsec-Uri` is `URL.String()` (path-only on a normal Traefik request). CrowdSec 1.8 then keys `__crowdsec_challenge` Secure on the parsed URI scheme, so the two cookies disagree and proto `http` with TLS still marks the gate cookie Secure.

## What Changes

- Move the inbound-request cluster into leaf `pkg/clientrequest` (exported type `Request`). Bouncer constructs it once after `GetRemoteIP`. The constructor owns the scheme token. Callers do not assign scheme later. Do not mutate the live `*http.Request`.
- Scheme rule (constructor only): trimmed `X-Forwarded-Proto` whole-value EqualFold `http` or `https` wins; else TLS non-nil → `https`, else `http`. Not a set proto: `wss`, empty, `https,http`, `Forwarded`, `Front-End-Https`, `X-Forwarded-Protocol`, `X-Scheme`, `URL.Scheme`. Do not re-check hop trust.
- Captcha `ServeHTTP`, `Check`, `Validate`, and `setGateCookie` take that value. Gate cookie Secure iff scheme is `https`. Captcha MUST NOT read proto or TLS. Proto `http` with TLS set → scheme `http` → cookie not Secure.
- AppSec `Query` takes that value instead of `ip` plus `*http.Request`. `X-Crowdsec-Appsec-Uri` is the wrapper's absolute URL (that scheme, `URL.Host` else `Request.Host`, path and query preserved). AppSec MUST NOT take scheme from `URL.Scheme` or rebuild proto-then-TLS. `X-Crowdsec-Appsec-Host` stays `Request.Host`.
- One Go httptest through the plugin forges TLS on/off and `X-Forwarded-Proto` and asserts Secure on `crowdsec_captcha_gate` and a stub AppSec `__crowdsec_challenge` (Secure iff the forwarded URI scheme is `https`). Not a real-stack HTTPS Traefik entrypoint.
- **Not BREAKING.** No public Traefik config keys. Cookie name, Path, HttpOnly, SameSite, MaxAge, Domain, HMAC, and bind-IP stay. This plugin still does not parse `__crowdsec_challenge`.

## Capabilities

### New Capabilities

- `core_plugin_clientrequest_inbound-request`: inbound request plus GetRemoteIP address plus constructor-owned scheme; absolute client-facing URL from that scheme.

### Modified Capabilities

- `core_plugin_middleware_captcha-gate`: gate cookie Secure iff the inbound-request scheme is `https`; captcha MUST NOT read proto or TLS.
- `core_plugin_appsec_client`: `Query` takes the inbound request value; `X-Crowdsec-Appsec-Uri` is that value's absolute URL; client address stays the wrapper's GetRemoteIP string.

## Impact

- New `pkg/clientrequest` (constructor, scheme, absolute URL). Delete `pkg/bouncer/clientrequest.go`.
- `pkg/bouncer/bouncer.go` and bouncer tests that build `clientRequest` (`testClientRequest`)
- `pkg/captcha/gate.go` `pkg/captcha/captcha.go` and captcha tests that pass a bare `*http.Request` plus `remoteIP`
- `pkg/appsec/query.go` and AppSec tests that call `Query` with `ip` plus `*http.Request`
- Live specs named above (deltas in this change)
- Usage packets `knowledge/devdocs/core_plugin_middleware_captcha-gate.md`, `core_plugin_appsec.md`, `core_plugin_ip.md` (implement / devdocs-impact)
- Go httptest dual-cookie Secure (plugin layer). Real-stack compose and mocklapi stay HTTP / no engine scheme check
