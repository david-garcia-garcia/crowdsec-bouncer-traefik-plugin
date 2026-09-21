# Explore

## Concepts

**Connection TLS**:
`r.TLS != nil` is the TLS state of the socket that reached Traefik (and then this plugin). Behind Cloudflare/ALB on an HTTP origin it is nil even when the browser used HTTPS.

**Entrypoint-sanitized proto**:
`X-Forwarded-Proto` on the request this plugin sees. Traefik’s entrypoint `XForwarded` already stripped or kept it. After that, empty proto is filled from `Request.TLS` (`https` / `http`). The host owner of whether that header is trustworthy is Traefik, not `GetRemoteIP`.

**Captcha gate cookie Secure**:
`http.Cookie.Secure` on `crowdsec_captcha_gate`. When false, a browser may send the grace cookie on a same-host HTTP entrypoint.

**GetRemoteIP hop trust**:
Owner of the **client address**. `BouncerForwardedInsecure` or `RemoteAddr` in `BouncerForwardedTrustedIPs` gates whether this plugin reads the custom **IP** header. That list can differ from Traefik’s entrypoint `forwardedHeaders.trustedIPs`. It does not own scheme.

## Decisions

- Reproduced on dest `setGateCookie`: `TLS == nil` + `X-Forwarded-Proto: https` issues `crowdsec_captcha_gate=v; Path=/; Max-Age=60; HttpOnly; SameSite=Lax` (no `Secure`). The same helper with `r.TLS` set adds `; Secure`. `Test_ServeHTTP_dummyProviderSolveIssuesGateCookie` passes and does not assert `Secure`. `TestHunt_gateCookieSecureWhenForwardedProtoHTTPS` is not in this tree.
- Set `Secure` when `r.TLS != nil` **or** the request’s `X-Forwarded-Proto` (as Traefik left it) is `https`. Do not copy `GetRemoteIP`’s hop walk or `BouncerForwardedInsecure` into captcha. That would reconstruct a host-owned fact and would miss operators whose Traefik entrypoint already kept proto while the plugin hop list is empty.
- Keep the Secure decision inside `setGateCookie` from `r` alone. Do not add hop-trust fields to `captcha.Client.New`. Do not put scheme on `clientRequest`. Do not change `GetRemoteIP` address selection.
- Parse: `http.CanonicalHeaderKey` / `Header.Get("X-Forwarded-Proto")`, trim space, `EqualFold` to `https` on that whole value. No comma split (Traefik writes a single token and compares with `== "https"`). Do not read `Forwarded`, `Front-End-Https`, `X-Forwarded-Protocol`, `X-Scheme`, or `BouncerForwardedHeader`. Do not treat `wss` as cookie Secure. Do not use `r.URL.Scheme`.
- Regression test lives in `pkg/captcha` next to the other gate tests (`Test_setGateCookie_…`), not a `TestHunt_*` name. Cover forwarded-https + `TLS == nil`, TLS-on, and proto `http` / absent.
- Update `core_plugin_middleware_captcha-gate` so Secure is TLS **or** forwarded https. Other cookie attributes stay as specified.
- Usage packet `core_plugin_middleware_captcha-gate.md` does not mention Secure today; leave it for implement / devdocs-impact. No new Language term.
- Research: `knowledge/research/ext_traefik_forwardedheaders_x-forwarded-proto/`.

```
  Cloudflare/ALB HTTPS
           │
           ▼
  Traefik entrypoint XForwarded
  (trustedIPs / insecure)
           │
           ├─ untrusted: strip proto, set from r.TLS → http when TLS nil
           └─ trusted: keep X-Forwarded-Proto: https
           │
           ▼
  plugin setGateCookie
           │
           ├─ r.TLS != nil        → Secure
           └─ proto EqualFold https → Secure
```

## Open questions

- Q: Who already owns client HTTPS / the trust hop for proto?
  Decision: assumed — Traefik entrypoint `forwardedHeaders` owns whether `X-Forwarded-Proto` is trustworthy and what value the plugin sees. `r.TLS` owns connection TLS to Traefik. `pkg/ip.GetRemoteIP` owns client address only. Reuse the sanitized header plus `r.TLS`. Do not re-derive hop trust in captcha or extend `GetRemoteIP` to return scheme.
  By: propose

- Q: How do `BouncerForwardedTrustedIPs` / `BouncerForwardedInsecure` reach `setGateCookie`?
  Decision: assumed — they do not. Ticket asked to reuse that model; Traefik already applied the equivalent gate. `setGateCookie` keeps reading only `r`. No `Client` fields, no bouncer `New` signature change.
  By: propose

- Q: Exact `X-Forwarded-Proto` parse (list, case, aliases)?
  Decision: assumed — trim `Header.Get("X-Forwarded-Proto")` and `EqualFold` to `https` on the whole value. Single token. No comma walk, no RFC 7239 `Forwarded`, no vendor aliases, not `wss`.
  By: propose

- Q: Where should the named hunt test live?
  Decision: assumed — `pkg/captcha` gate tests with a `Test_setGateCookie_` name. Do not add `TestHunt_gateCookieSecureWhenForwardedProtoHTTPS`. Dest has no `TestHunt_*` functions.
  By: propose

- Q: Does the captcha-gate spec stay TLS-only for Secure?
  Decision: assumed — no. Propose updates the Secure clause to TLS or forwarded https. HttpOnly, Path, SameSite, MaxAge, no Domain stay.
  By: propose
