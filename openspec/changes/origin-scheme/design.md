## Context

See proposal.md — Why. Dest `clientRequest` is unexported in `pkg/bouncer` with address fields and no scheme. `setGateCookie` ORs TLS with proto `https`. `Query` sends `httpReq.URL.String()`. Identity owners: Traefik entrypoint owns whether `X-Forwarded-Proto` is trustworthy; `Request.TLS` owns the socket to Traefik; `GetRemoteIP` owns client address; `Request.Host` owns Host; the new constructor owns the scheme token. Research: `knowledge/research/ext_traefik_forwardedheaders_x-forwarded-proto/`, `knowledge/research/ext_crowdsec_appsec_bot-detection/` (`v1.8.0` Secure iff parsed URI scheme is `https`).

## Goals / Non-Goals

**Goals:**
- Leaf `pkg/clientrequest` with constructor-owned scheme and absolute URL.
- Captcha Secure and AppSec URI consume that scheme; neither recalculates proto-then-TLS.
- Go httptest dual-cookie Secure through the plugin.
- Real-stack Pester on the HTTP entrypoint: trusted `X-Forwarded-Proto` decides Secure on both cookies.

**Non-Goals:**
- Changing GetRemoteIP hop walking.
- Trusting `URL.Scheme`; comma-split proto; RFC 7239 `Forwarded`; vendor proto aliases; copying raw `wss` into the URI.
- Writing scheme onto the live `http.Request`.
- HTTPS Traefik entrypoint or teaching mocklapi CrowdSec's scheme check.
- Widening path-only captcha helpers to the wrapper.
- Parsing `__crowdsec_challenge` in this plugin.
- Gate HMAC, bind-IP, grace, other cookie attributes.

## Decisions

1. **Package `pkg/clientrequest`, exported type `Request`.** Embed the live `*http.Request` pointer. Address, scheme, and absolute URL are unexported snapshots with getters. Call sites keep `req`. Alternative: keep the type in `pkg/bouncer` — rejected; captcha and AppSec must take the value without importing bouncer.

2. **`New` after GetRemoteIP owns scheme and the address snapshot.** When the parsed address is non-nil, `New` stores `ipAddr.String()` as the remote IP. An unparsed extract stays as `GetRemoteIP` returned it, for fail logs. The family is `ip.FamilyOfIP` of that parsed address. Alternative: captcha reads proto — rejected; that is a second scheme owner. Alternative: pass the family into `New` — rejected; it is derived from the address `New` already stores.

3. **`AbsoluteURL` on `Request`.** Scheme from the constructor, host from `URL.Host` else `Request.Host`, path and query from `URL`. AppSec copies that string onto `X-Crowdsec-Appsec-Uri`. Alternative: AppSec rebuilds `url.URL` — rejected; that would re-derive host fallback beside the cluster.

4. **Captcha `ServeHTTP` / `Check` / `Validate` / `setGateCookie` take `Request`.** `setGateCookie` sets Secure iff `Scheme() == "https"`. Path-only helpers stay on `*http.Request`. Alternative: pass only the scheme string into `setGateCookie` — rejected once `ServeHTTP` already has the cluster; do not grow a parallel scheme argument.

5. **AppSec `Query(req Request, pol Policy)`.** `X-Crowdsec-Appsec-Ip` from `req` remoteIP. URI from `AbsoluteURL()`. Host header stays `Request.Host`. Alternative: keep `(ip string, *http.Request)` and add scheme — rejected; those facts already travel together.

6. **Dual-cookie coverage is two layers.** Go httptest in `pkg/bouncer` forges `req.TLS` and `X-Forwarded-Proto`; stub AppSec sets `__crowdsec_challenge` Secure iff the forwarded URI scheme is `https`. Real-stack Pester stays on the HTTP entrypoint: the published-port peer is already in `forwardedHeaders.trustedIPs`, so Traefik keeps the test's `X-Forwarded-Proto`. CrowdSec `GrantChallengeCookie` on `/origin-scheme` mints the real challenge cookie. Alternative: an HTTPS Traefik entrypoint — rejected; proto from a trusted hop is the signal Traefik already hands the plugin.

7. **Rejected:** keep Secure inside `setGateCookie` from `r` alone (archived 2026-09-18 explore). This ask shares scheme with AppSec.

## Risks / Trade-offs

- [Explicit proto `http` with TLS set no longer marks the gate cookie Secure] → that is the asked proto-wins rule; dest `Test_setGateCookie_connectionTLSSetsSecure` must not hide a missing proto (constructor case + captcha scheme-http case).
- [A Traefik install that left a forged proto `https` on HTTP] → constructor trusts the header Traefik already kept. Mitigation is entrypoint `forwardedHeaders`, not a second hop list here.
- [CrowdSec official protocol example is path-only URI] → `v1.8.0` source keys Secure on parsed scheme; send the absolute URL this change specifies.
- [Yaegi must load the new package] → it follows the plugin module import graph (`bouncer` / `captcha` / `appsec` → `clientrequest`). No extra interpreter table.

## Migration Plan

None. No Traefik config keys. Outstanding gate cookies remain valid. AppSec challenge cookies minted after deploy pick up Secure from the new URI scheme.

## Open Questions

None — ticket decisions stand on `explore.md`.
