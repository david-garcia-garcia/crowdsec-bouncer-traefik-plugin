# GetRemoteIP trusts X-Forwarded-For without a RemoteAddr trusted-proxy gate

slug: ip-xff-trust-gate
component: ip
severity: security

## Problem
`GetRemoteIP` walks forwarded-header hops but does not require `RemoteAddr` to be a trusted proxy. With an empty default trusted-hop list, any client can set the header and become that IP for decisions. Malformed-hop fail-closed (`tech_trustipfail`) is untested.

Related findings (same change, `pkg/ip` only):

### Forwarded-header client IP is chosen without verifying the socket peer is a trusted proxy
`GetRemoteIP` walks `X-Forwarded-For` (or the custom header) and returns the first hop not in `ForwardedHeadersTrustedIPs`, but it never checks that `req.RemoteAddr` itself is a trusted proxy before trusting any header value. A client that connects directly to Traefik can supply a forged chain (`victim-ip, trusted-proxy-ip`) and be identified as `victim-ip`. With the default empty trusted-hop list, any single spoofed header value is accepted as the client address whenever the header is present.

When the forwarded header is `203.0.113.10, 10.0.0.1` and `10.0.0.1` is in the trusted-hop pool, `GetRemoteIP` returns `203.0.113.10` even if `RemoteAddr` is an untrusted address such as `198.51.100.5:443`. When the trusted-hop pool is empty and the header is `203.0.113.10`, the rightmost hop is immediately treated as the client (nothing is trusted, so the first walk iteration wins) instead of falling back to `RemoteAddr`.

Before walking the forwarded header, require that the host extracted from `req.RemoteAddr` is in the trusted-hop pool (or treat a missing/empty pool as “trust no forwarded hops” and use `RemoteAddr` only). Add unit tests: direct connection + forged multi-hop header; empty trusted pool + header present → `RemoteAddr`; legitimate proxy chain unchanged.

### Unparseable forwarded hops are fail-closed in production but untested in pkg/ip
When the header walk hits a hop that `net.ParseIP` cannot parse, `getIP` stops immediately and returns that raw string with a nil `net.IP`. The bouncer then remediates with `plugin:tech_trustipfail`. This spoofing-adjacent edge path has no unit test, so regressions in hop trimming, walk order, or parse handling would not be caught.

For header value `203.0.113.10, not-an-ip, 10.0.0.1` with `10.0.0.1` trusted, the walk checks `10.0.0.1` (trusted, skipped), then `not-an-ip` (parse fails) and returns `"not-an-ip"` with nil `net.IP`.

Add `TestGetRemoteIP` cases for: malformed hop between trusted and client IPs; malformed rightmost hop; port-suffixed hop (`203.0.113.10:443`). Assert returned string, nil/non-nil parsed IP, and document the intended fail-closed contract for bouncer callers.

## Desired
Only honor forwarded headers when `RemoteAddr` is in the trusted-proxy set (fail closed if the list is empty: use `RemoteAddr`). Keep unparseable-hop fail-closed. Tests for spoofing and malformed hops.

## Scope bound
`pkg/ip` only. Do NOT change `pkg/iplookup`.

## Out of scope
- `pkg/iplookup`
- Traefik entrypoint `forwardedHeaders.trustedIPs` configuration (expected complementary layer per e2e specs)
- `ClientTrustedIPs` bypass after identity is already chosen
- Whether fail-closed vs skip-unparseable-hop is the better product choice (current code is intentionally fail-closed)

## Grouped findings
ip-xff-trust-gate, xff-without-remoteaddr-trust-gate, getremoteip-unparseable-hop-untested
