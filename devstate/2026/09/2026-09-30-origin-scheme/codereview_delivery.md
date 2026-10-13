# Delivery

## Motivation

Captcha gate cookie `crowdsec_captcha_gate` and CrowdSec AppSec bot-detection cookie `__crowdsec_challenge` both need the client-facing scheme. Traefik may leave `X-Forwarded-Proto` when the entrypoint trusts forwarded headers; `Request.TLS` is the socket to Traefik and is often nil after TLS termination. GetRemoteIP already chose the client address. It does not own scheme.

The captcha gate set `Secure` when `Request.TLS` was non-nil **or** trimmed `X-Forwarded-Proto` EqualFold `https` (whole value). Captcha read proto and TLS itself. Explicit proto `http` with TLS set still got `Secure`. AppSec `X-Crowdsec-Appsec-Uri` was `httpReq.URL.String()`. A normal Traefik server request is origin-form: empty `URL.Scheme` and `URL.Host`, path and query only (`/foo?q=1`). CrowdSec 1.8 parses that header into `request.URL` and sets `__crowdsec_challenge` `Secure` iff `request.URL.Scheme == "https"`. Path-only URI yields an empty Scheme, so the challenge cookie is not `Secure` even when the browser is on HTTPS.

Left alone, HTTPS clients behind Traefik receive the challenge cookie without `Secure`. The two cookies can disagree: gate `Secure` from the OR, challenge never `Secure` on origin-form. Proto `http` plus TLS over-marks the gate cookie `Secure`. Nothing asserted `Secure` on both cookies together.

Priority: P2 — HTTPS clients get the AppSec challenge cookie without Secure, limited to bot-detection and that cookie

## Implementation

`pkg/clientrequest.New` fills one inbound `Request` after GetRemoteIP. The constructor owns the scheme token: trimmed `X-Forwarded-Proto` whole-value EqualFold `http` or `https` wins; otherwise TLS non-nil is `https`, else `http`. Values that are not an exact proto (`wss`, empty, `https,http`, `URL.Scheme`) fall through to TLS. Callers do not assign scheme. The live `*http.Request` is not written.

Captcha `ServeHTTP`, `Check`, `Validate`, and `setGateCookie` take that value. Gate cookie `Secure` iff `Scheme()` is `https`. Captcha does not read proto or TLS.

AppSec `Query` takes the same value. `X-Crowdsec-Appsec-Uri` is `AbsoluteURL()`: constructor scheme, `URL.Host` else `Request.Host`, path and query preserved. `X-Crowdsec-Appsec-Host` stays `Request.Host`.

A Go httptest through the plugin forges proto and TLS and asserts `Secure` on `crowdsec_captcha_gate` and on a stub AppSec `__crowdsec_challenge` when the forwarded URI scheme is `https`.

## What this changes
**Operators.** `X-Crowdsec-Appsec-Uri` sent to CrowdSec is an absolute URL (scheme, host, path and query), not origin-form.
**Admin users.** None.
**Developers.** Captcha `ServeHTTP`, `Check`, and `Validate`, and AppSec `Query`, take `clientrequest.Request` instead of `*http.Request` plus a parallel IP; scheme is constructor-owned (`New`, `Scheme()`, `AbsoluteURL()`).
**End users.** `crowdsec_captcha_gate` and `__crowdsec_challenge` set `Secure` when the client-facing scheme is `https`, and omit it when the scheme is `http` (including explicit proto `http` with TLS).
