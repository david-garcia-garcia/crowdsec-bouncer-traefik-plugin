## Context

`GetRemoteIP` is the client-address owner. Traefik's entrypoint already strips `X-Real-Ip` from untrusted peers (v3.6.8 `forwarded_header.go`). The plugin's peer gate is redundant in that topology and cannot express "trust any peer, take the header" because the same list is the hop-skip pool.

## Goals / Non-Goals

**Goals:**
- Default path unchanged, including catch-all silent fallback.
- Explicit opt-in that skips the checker and treats the header as one address.
- Default header `X-Real-Ip` when the flag is on and the custom name is still `X-Forwarded-For`.

**Non-Goals:**
- New `ValidateParams` rejection or validate-time warning.
- Putting the flag on `PoolStrategy`.
- Captcha, AppSec, cache, LAPI, reclaim.
- Changing `ClientTrustedIPs`.

## Decisions

1. `GetRemoteIP(req, strategy, customHeader, insecure bool)` — flag is an argument, not a checker field.
2. Insecure path: `SplitHostPort` first; trim `Header.Get` with no comma split; empty → `RemoteAddr` host; `net.ParseIP` or raw string + nil parse.
3. Effective name resolved in `bouncer.New` only. Default `X-Forwarded-For` plus the flag → `X-Real-Ip`. Log: `ForwardedHeadersInsecure enabled, using header <name>`.
4. Yaegi: no generics, no `atomic.Pointer[T]`. Plain bool field on `Bouncer`.

## Risks / Trade-offs

- Flag on without a sanitizing Traefik entrypoint lets the client pick the remediations IP. README states that. Accepted, same class as `CrowdsecLapiTLSInsecureVerify`.
- Writing `forwardedHeadersCustomName: X-Forwarded-For` beside the flag is indistinguishable from the default and becomes `X-Real-Ip`. Accepted; log + README disclose it.

## Migration Plan

Default false. Operators who want the Traefik-sanitized address set `forwardedHeadersInsecure: true` and keep the entrypoint `forwardedHeaders.trustedIPs` (not `insecure: true`).

## Open Questions

None — ticket decisions stand.
