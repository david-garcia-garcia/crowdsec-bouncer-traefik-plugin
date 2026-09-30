# Explore

## Concepts

One inbound-request owner should hold the address GetRemoteIP already chose **and** the client-facing scheme. Captcha gate cookie Secure and AppSec `X-Crowdsec-Appsec-Uri` both need that scheme. Dest computes Secure inside captcha (TLS **or** proto `https`) and sends AppSec a path-only `URL.String()`.

```
  Traefik entrypoint XForwarded          GetRemoteIP
  (trustedIPs / insecure)                (client address only)
           │                                    │
           ├─ kept/stripped X-Forwarded-Proto   │
           └─ Request.TLS = socket to Traefik   │
           │                                    │
           ▼                                    ▼
     leaf constructor (scheme + address on one Request)
           │
           ├─ captcha setGateCookie  Secure iff scheme == https
           └─ appsec Query           X-Crowdsec-Appsec-Uri = absolute URL
                    │
                    ▼
           CrowdSec 1.8 url.Parse(Uri) → request.URL
                    └─ __crowdsec_challenge Secure iff URL.Scheme == "https"
```

| Unit | Path | Job |
| --- | --- | --- |
| clientRequest | `pkg/bouncer/clientrequest.go` | Unexported inbound request + GetRemoteIP address. No scheme. No constructor. |
| Bouncer ServeHTTP | `pkg/bouncer/bouncer.go` | GetRemoteIP then struct literal. Passes `req.Request` + `req.remoteIP` into captcha and AppSec. |
| Captcha gate | `pkg/captcha/gate.go` `setGateCookie` | Secure when `r.TLS != nil` **or** trimmed proto EqualFold `https`. Reads proto and TLS itself. |
| Captcha client | `pkg/captcha/captcha.go` | `ServeHTTP` / `Check` / `Validate` take `*http.Request` plus parallel `remoteIP`. Path-only helpers stay on `*http.Request`. |
| AppSec Query | `pkg/appsec/query.go` | `Query(ip, *http.Request, Policy)`. URI header is `httpReq.URL.String()`. Host header is `httpReq.Host`. |
| GetRemoteIP | `pkg/ip` | Owner of **client address**, not scheme. Out of scope to change hop walking. |
| Traefik proto | `knowledge/research/ext_traefik_forwardedheaders_x-forwarded-proto/` | Entrypoint owns whether `X-Forwarded-Proto` is trustworthy. |
| CrowdSec challenge cookie | `knowledge/research/ext_crowdsec_appsec_bot-detection/` | Engine mints `__crowdsec_challenge`; this plugin relays `user_cookies`. Secure is engine-side. |
| Captcha-gate spec | `openspec/specs/core_plugin_middleware_captcha-gate/spec.md` | Live: Secure is TLS **or** proto `https`. Scenario "Connection TLS sets Secure" has no proto. |
| AppSec client spec | `openspec/specs/core_plugin_appsec_client/spec.md` | Live Query contract. URI shape is not frozen. |
| Bot-detection spec | `openspec/specs/core_plugin_appsec_bot-detection/spec.md` | Relays cookies as AppSec sent them. This plugin does not parse `__crowdsec_challenge`. |
| Real-stack e2e | `tests/e2e/real/` | HTTP entrypoint `:80` with trusted forwarded IPs. Asserts cookie **presence**, not Secure. |
| Mock AppSec | `tests/e2e/mock/mocklapi/main.go` | Returns `__crowdsec_challenge=e2e; Path=/; HttpOnly` (no Secure, no scheme check). |

### Reproduce

**Reproduced** (dest matches the claimed failure; existing tests do not catch it).

1. `go test ./pkg/captcha -run Test_setGateCookie -count=1` from worktree root: **PASS**. Cases cover forwarded https, TLS, and proto http/wss/absent/empty with TLS nil. They do **not** cover proto `http` plus TLS set.

2. Throwaway `$TEMP/origin-scheme-repro` (`go run` of dest `setGateCookie` OR vs the asked proto-then-TLS rule, plus `url.Parse` of `URL.String()`):
   - dest OR, proto `http`, TLS set → **Secure=true**; asked scheme `http` (cookie must not be Secure).
   - dest OR, proto `https`, TLS nil → Secure=true (same as asked).
   - `httptest.NewRequest(GET, "/foo?q=1")` with `Host=app.example`: `URL.String()="/foo?q=1"`, Scheme and URL.Host empty.
   - `url.Parse` of that string: Scheme empty → CrowdSec Secure would **not** set.
   - asked absolute `https://app.example/foo?q=1`: Scheme `https` → Secure would set.
   - `net/http` `httptest.NewServer` inbound request: `URL.String()="/bar?x=1"`, Scheme and URL.Host empty, `Request.Host` is the listen host. Same shape as a normal Traefik server request.

3. `pkg/appsec/query.go` sets `X-Crowdsec-Appsec-Uri` to `httpReq.URL.String()`. Query tests use `httptest.NewRequest(..., "http://localhost/", ...)` (scheme present) and do not assert that header.

4. Dual-cookie Secure e2e (TLS / `X-Forwarded-Proto`, both cookie names): **not found**. Real Pester: `tests/e2e/real/captcha.Tests.ps1` `crowdsec_captcha_gate=`; `tests/e2e/real/appsec.Tests.ps1` `__crowdsec_challenge` presence. Compose: `--entrypoints.web.address=:80` only.

### Call sites (bounded)

Roots searched: worktree `pkg/**/*.go` excluding `vendor/` for `clientRequest`, `testClientRequest(`, `captchaClient.(ServeHTTP|Check|Validate|IsCustomResourceRequest|IsCaptchaFormPost|WriteSolvedRedirect)`, `func (c *Client) Query`, `appsecClient.Query(`, `setGateCookie(`.

| Contract | Count | Notes |
| --- | --- | --- |
| `type clientRequest` | **1** | `pkg/bouncer/clientrequest.go` |
| ServeHTTP construction | **1** | `pkg/bouncer/bouncer.go` after GetRemoteIP |
| Production methods taking `clientRequest` | **14** | same file (`passOrCaptchaRule` through `handleAppsecResponseServeHTTP`) |
| `testClientRequest` helper + uses | **1 + ~40** | `pkg/bouncer/zzz_*.go` only |
| `appsec.Client.Query` production | **1** | `pkg/bouncer/bouncer.go` `applyAppsecServeHTTP` |
| `Query(` in `pkg/appsec` tests | **all remaining** | `zzz_query_test.go`, `zzz_failure_action_test.go`, `zzz_nil_transport_test.go`, `zzz_timeout_test.go` |
| `captcha.Client.ServeHTTP` production | **1** | `handleCaptchaKindServeHTTP` |
| `Check` production | **1** | same |
| `Validate` production | **1** | `ServeHTTP` in `pkg/captcha/captcha.go` |
| `setGateCookie` production | **1** | Pass path in `ServeHTTP` |
| `IsCustomResourceRequest` / `IsCaptchaFormPost` / `WriteSolvedRedirect` production | **1 each** | bouncer; no parallel IP |
| New leaf package | **0** | not found |

### Outside facts

- Traefik proto trust: `knowledge/research/ext_traefik_forwardedheaders_x-forwarded-proto/`.
- AppSec protocol URI meaning ("Original URI" only): `knowledge/research/ext_crowdsec_appsec_protocol/`.
- CrowdSec 1.8 `__crowdsec_challenge` Secure: `github.com/crowdsecurity/crowdsec@v1.8.0` (`cc76dbbce40bd2e6a3ce1ba07e3c41d8b462de66`) `pkg/appsec/challenge/challenge.go` (Secure iff `request.URL.Scheme == "https"` on mint and allowlist seal) and `pkg/appsec/request.go` (`url.Parse` of `X-Crowdsec-Appsec-Uri` into `originalHTTPRequest.URL`). Research folder `ext_crowdsec_appsec_bot-detection/` is being updated with this pin (delegate in flight).
- Go server origin-form URL: reproduced above; Scheme and URL.Host empty.

## Decisions

- Chosen seam: new leaf `pkg/clientrequest`, exported type `Request` (callers keep `req`). Constructor after GetRemoteIP owns scheme. Package imports neither bouncer, captcha, nor appsec. Do not mutate the live `*http.Request`.
- Scheme rule (constructor only): trimmed `X-Forwarded-Proto` whole-value EqualFold `http` or `https` wins; else TLS non-nil → `https`, else `http`. Not a set proto: `wss`, empty, `https,http`, `Forwarded`, `Front-End-Https`, `X-Forwarded-Protocol`, `X-Scheme`, `URL.Scheme`. No hop-trust re-check.
- Captcha `ServeHTTP`, `Check`, `Validate`, and `setGateCookie` take that value (or scheme from it). Captcha must not read proto or TLS. Secure iff scheme is `https`. Proto `http` with TLS set → not Secure.
- AppSec `Query` takes that value instead of `ip` plus `*http.Request`. `X-Crowdsec-Appsec-Uri` is the wrapper's absolute URL: that scheme, `URL.Host` when set else `Request.Host`, Path and RawQuery preserved. Do not use `URL.Scheme`. Leave `X-Crowdsec-Appsec-Host` as `Request.Host` unless filling URI host requires the empty-`URL.Host` case (already `Request.Host`).
- Path-only captcha helpers (`IsCustomResourceRequest`, `IsCaptchaFormPost`, `WriteSolvedRedirect`, `gateCookieValue`, `RequestDomain`) stay on `*http.Request` / host string.
- Live spec `core_plugin_middleware_captcha-gate`: rewrite Secure to the shared scheme; add proto `http` + TLS → not Secure. Other cookie attributes stay. AppSec URI shape is new on `core_plugin_appsec_client` (no live URI freeze today). Bot-detection spec stays relay-as-sent.
- Dual-cookie test: one Go httptest through the plugin that forges TLS on/off and `X-Forwarded-Proto`, asserts `crowdsec_captcha_gate` Secure and a stub AppSec `__crowdsec_challenge` Secure when the forwarded URI scheme is `https` (mirrors CrowdSec). Do not add an HTTPS Traefik entrypoint. Do not teach mocklapi CrowdSec's scheme check for this ticket.
- Rejected: keep Secure inside `setGateCookie` from `r` alone (archived 2026-09-18 explore). This ask shares scheme with AppSec.
- Rejected: copy GetRemoteIP hop trust into captcha; trust `URL.Scheme`; comma-split proto; write scheme onto the live request; copy raw `wss` into the URI. Out of scope.
- Live contract: `core_plugin_middleware_captcha-gate` (Secure clause MODIFIED). `core_plugin_appsec_client` exists but does not freeze URI shape. `core_plugin_appsec_bot-detection` does not parse the challenge cookie.

## Open questions

- Q: Who already owns client HTTPS / Host / the trust hop for proto?
  Rank: bounded asked — existing Traefik proto contract and GetRemoteIP address owner, enumerated (research packet + `pkg/ip`); criterion 2 names the scheme rule and forbids hop re-check
  Decision: assumed — Traefik entrypoint `forwardedHeaders` owns whether `X-Forwarded-Proto` is trustworthy. `Request.TLS` owns connection TLS to Traefik. `pkg/ip.GetRemoteIP` owns client address. `Request.Host` owns Host. The new constructor owns the scheme **token** derived from proto-then-TLS. AppSec URI host reuses `Request.Host` when `URL.Host` is empty. Do not re-derive hop trust in captcha or AppSec.
  By: explore

- Q: What is the leaf package and type name?
  Rank: additive asked — new package this change creates; criterion 1 names "a new leaf package" with no identifier
  Decision: assumed — `pkg/clientrequest`, exported type `Request`. Fields or accessors for the embedded request, `remoteIP` / `ipAddr` / `ipType`, and `scheme`. Call sites keep the name `req`. Not Wrapper, Context, or a second address field.
  By: explore

- Q: Captcha signatures that take only `*http.Request` — widen them to the wrapper?
  Rank: additive asked — leaving them is not a reshape; criterion 1 names "instead of a bare `*http.Request` plus a parallel remoteIP string"; those have no parallel IP
  Decision: assumed — leave `IsCustomResourceRequest`, `IsCaptchaFormPost`, `WriteSolvedRedirect`, `gateCookieValue`, and `RequestDomain` on `*http.Request` / host string. Out of scope already names captcha redirect target and custom-resource path checks. `setGateCookie` must take the wrapper (or its scheme) because captcha must not read proto or TLS.
  By: explore

- Q: URI host when both `URL.Host` and `Request.Host` are set?
  Rank: additive asked — host fallback on the URI builder this change creates; criterion 4 names only the empty-`URL.Host` case
  Decision: assumed — use `URL.Host` when non-empty, else `Request.Host`. Matches `url.URL` once scheme is set. Traefik server requests have empty `URL.Host`.
  By: explore

- Q: Does CrowdSec 1.8 still key `__crowdsec_challenge` Secure on `request.URL.Scheme == "https"`?
  Rank: additive asked — new URI shape this change sends; criterion 4 cites that engine check
  Decision: resolved — yes, on `github.com/crowdsecurity/crowdsec@cc76dbbce40bd2e6a3ce1ba07e3c41d8b462de66` (`v1.8.0`) `pkg/appsec/challenge/challenge.go` (mint and allowlist seal). `pkg/appsec/request.go` assigns `url.Parse(X-Crowdsec-Appsec-Uri)` to `originalHTTPRequest.URL`. Path-only URI → empty Scheme → no Secure. Official protocol page does not mention Secure.
  By: explore

- Q: Where does the dual-cookie Secure e2e live?
  Rank: additive asked — new test; criterion 5 names TLS on/off, `X-Forwarded-Proto`, and both cookie names
  Decision: assumed — Go httptest through the plugin (forge `req.TLS` and proto). Stub AppSec sets `__crowdsec_challenge` Secure iff the forwarded URI scheme is `https`. Real-stack compose is HTTP `:80` only (`tests/e2e/real/config/docker-compose.test.yml`); adding an HTTPS entrypoint is not in the ask. Mocklapi does not implement CrowdSec's scheme check. Criterion 5's TLS-on clause cannot be forged in dest Pester without that entrypoint.
  By: explore

- Q: Does the captcha-gate spec keep TLS **or** proto `https`?
  Rank: bounded asked — one live spec leaf, callers are dest tests + usage packet; criterion 3 names Secure iff shared scheme `https` and proto `http` + TLS → not Secure
  Decision: assumed — no. Propose rewrites the Secure clause to the shared scheme. Add a scenario for explicit proto `http` with TLS set. HttpOnly, Path, SameSite, MaxAge, no Domain stay. Dest `Test_setGateCookie_connectionTLSSetsSecure` must gain "no proto" or it will hide the new case.
  By: explore
