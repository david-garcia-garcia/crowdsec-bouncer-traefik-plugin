## Context

`bouncer.New` builds `serverPoolStrategy` from `ForwardedHeadersTrustedIPs`. Today that Checker only skips hops during the header walk; it does not gate whether headers may be read. Docs already say headers must come from a trusted hop.

## Goals / Non-Goals

**Goals**
- Prevent direct clients from spoofing client IP via forwarded headers.
- Empty trusted-hop pool → RemoteAddr only (fail closed on forwarded data).
- Preserve hop-skipping and unparseable-hop fail-closed semantics for legitimate proxy chains.
- Unit-test coverage for spoofing, empty pool, malformed hops.

**Non-Goals**
- Change `pkg/iplookup`, bouncer wiring, or Traefik entrypoint `forwardedHeaders.trustedIPs`.
- Change fail-closed vs skip-unparseable-hop product policy.
- Separate RemoteAddr trusted pool from hop-skipping pool.

## Decisions

- **Gate in `GetRemoteIP`**: Extract host from `RemoteAddr` via `net.SplitHostPort`, parse, call `strategy.Checker.ContainsIP`. If checker nil, pool empty (no entries trusted), or peer not trusted → skip `getIP` and return RemoteAddr host.
- **Reuse same Checker**: One `PoolStrategy` from config; no bouncer changes.
- **Empty pool detection**: `ContainsIP` on any address returns false for empty pool; additionally treat nil checker as trust nothing. Explicit early return when walk would be meaningless.

## Risks / Trade-offs

- Operators who relied on header-only client IP without listing proxies will now get `RemoteAddr` until they configure `forwardedHeadersTrustedIps` — correct security posture.
- Existing unit tests that set untrusted `RemoteAddr` while expecting header walk must use trusted proxy `RemoteAddr`.

## Migration Plan

None — behavior fix only. Configure `forwardedHeadersTrustedIps` to include Traefik/reverse-proxy addresses when behind a proxy.

## Open Questions

None — explore decisions recorded on `devstate/explore.md`.
