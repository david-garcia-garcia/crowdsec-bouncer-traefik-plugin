## Context

See proposal.md Why. Dest `setGateCookie` sets `http.Cookie.Secure` only when `r.TLS != nil`. Traefik's entrypoint `XForwarded` already owns whether `X-Forwarded-Proto` is trustworthy: untrusted peers lose the header and get proto rewritten from `Request.TLS`; a kept `https` means the hop was trusted or `forwardedHeaders.insecure` was on. `GetRemoteIP` owns client address, not scheme. Research: `knowledge/research/ext_traefik_forwardedheaders_x-forwarded-proto/`.

## Goals / Non-Goals

**Goals:**
- Secure from `r` alone: connection TLS **or** Traefik-left `X-Forwarded-Proto` EqualFold `https`.
- Regression tests in `pkg/captcha` next to existing gate tests.

**Non-Goals:**
- Hop-trust fields on `captcha.Client` or a `New` signature change.
- Copying `GetRemoteIP`'s CIDR walk or `ForwardedHeadersInsecure` into captcha.
- Changing `GetRemoteIP` address selection or putting scheme on `clientRequest`.
- Other cookie attributes, HMAC, bind-IP, grace, siteverify, AppSec, LAPI, cache, Redis.
- Comma-split proto, RFC 7239 `Forwarded`, vendor aliases, `wss` as cookie Secure, `r.URL.Scheme`.
- Usage-packet Secure text (implement / devdocs-impact).

## Decisions

1. **Owner of proto trust is Traefik, not this plugin.** Read the header the entrypoint already sanitized. Alternative: replay `ForwardedHeadersTrustedIPs` / `ForwardedHeadersInsecure` in captcha — rejected; that reconstructs a host-owned fact and misses operators whose entrypoint kept proto while the plugin hop list is empty (`skill:sbs-dev-commandments:One job, one owner`).

2. **Parse is one token.** `Header.Get("X-Forwarded-Proto")`, trim space, `EqualFold` to `https` on the whole value. Traefik writes a single token and compares with `== "https"`. No comma walk. `wss` is not cookie Secure.

3. **Keep the decision in `setGateCookie`.** `ServeHTTP` already passes `rw, r`. No Client fields, no bouncer wiring.

4. **Tests are `Test_setGateCookie_…` in `pkg/captcha/zzz_gate_test.go`.** Cover forwarded-https + `TLS == nil`, TLS-on, and proto `http` / absent / `wss`. Do not add `TestHunt_*`.

## Risks / Trade-offs

- [A Traefik install with empty `trustedIPs` and `insecure: false` still yields proto `http` when TLS is nil] → Secure stays off; that is the entrypoint contract, not a plugin miss.
- [A forged `X-Forwarded-Proto: https` on an HTTP entrypoint that did not strip it] → Secure is set. Mitigation is Traefik `forwardedHeaders`, not a second hop list here.
- [Case-insensitive compare vs Traefik's exact `== "https"`] → Accept EqualFold so `HTTPS` still marks Secure; Traefik rewrite emits lowercase.

## Migration Plan

None. Cookie issuance changes only the Secure flag. Outstanding cookies remain valid.

## Open Questions

None — explore.md decisions stand.
