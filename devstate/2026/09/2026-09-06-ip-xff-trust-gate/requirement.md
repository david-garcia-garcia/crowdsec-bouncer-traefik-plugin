# Requirement
IssueKey: 2026-09-06-ip-xff-trust-gate

## Problem
`GetRemoteIP` honors forwarded headers without verifying `req.RemoteAddr` is a trusted proxy. A direct client can forge `victim-ip, trusted-proxy-ip` and be identified as the victim. With an empty trusted-hop pool (the default), any present header value wins over the socket peer. Unparseable-hop fail-closed behavior exists but has no unit tests.

## Current (code)
- `pkg/ip/checker.go:102-127` — `PoolStrategy.getIP` walks the custom forwarded header right-to-left; returns the first hop not in `Checker`; never reads `req.RemoteAddr`.
- `pkg/ip/checker.go:133-144` — `GetRemoteIP` returns the header walk result when non-empty; `RemoteAddr` is used only when the header is empty or every hop is in the trusted pool.
- `pkg/ip/checker.go:117-120` — unparseable hop returns `(xffTrimmed, nil)` immediately; walk does not continue.
- `pkg/configuration/configuration.go:200` — default `ForwardedHeadersTrustedIPs` is an empty slice (context only; out of scope to change here).
- `pkg/ip/checker_test.go:107-163` — `TestGetRemoteIP` covers trusted-hop skipping, empty header, all-hops-trusted fallback, empty segments, custom header, and bad `RemoteAddr`; no direct-connection spoofing, empty-pool-with-header, or malformed-hop cases.
- `pkg/bouncer/bouncer.go:144-147` — nil `ipAddr` after `GetRemoteIP` triggers `OriginPluginTechTrustIPFail` (downstream consumer; not in scope to change).
- `knowledge/devdocs/core_plugin_decisionscope.md:59` — documents that headers must come from a trusted hop; code does not enforce that on `RemoteAddr`.
- `openspec/changes/archive/2026-09-06-parse-client-ip-once/specs/core_plugin_ip_radix-lookup/spec.md:4-16` — spec defines hop-skipping semantics but does not require a trusted `RemoteAddr` gate.

## Desired
- Before walking the forwarded header, require the host from `req.RemoteAddr` is in the trusted-hop pool; if the pool is empty, trust no forwarded hops and use `RemoteAddr` only.
- Keep unparseable-hop fail-closed (`nil` `net.IP` for unparseable hop).
- Add `TestGetRemoteIP` cases: direct connection + forged multi-hop header; empty trusted pool + header present → `RemoteAddr`; legitimate proxy chain unchanged; malformed hop between trusted and client IPs; malformed rightmost hop; port-suffixed hop (`203.0.113.10:443`).

## Affected
- `pkg/ip/checker.go` (`GetRemoteIP` / `PoolStrategy.getIP` or a RemoteAddr gate wrapper)
- `pkg/ip/checker_test.go`

## Out of scope
- `pkg/iplookup` (explicit bound)
- Traefik entrypoint `forwardedHeaders.trustedIPs` configuration
- `ClientTrustedIPs` bypass after identity is chosen
- Changing fail-closed vs skip-unparseable-hop product policy
- `pkg/configuration/configuration.go` default or validation changes
- `pkg/bouncer/bouncer.go` changes

## Unknowns
- Whether the RemoteAddr trusted-proxy check reuses the same `PoolStrategy.Checker` instance wired from `ForwardedHeadersTrustedIPs` or needs a separate pool (ticket text uses trusted-hop pool; explore may confirm wiring in bouncer only reads config once).

## Tensions
- Docs (`knowledge/devdocs/core_plugin_decisionscope.md`) say headers must come from a trusted hop; `GetRemoteIP` does not gate on `RemoteAddr`.
- Archived spec defines hop-skipping without a RemoteAddr gate; this change may need a spec delta in propose.
- Default empty `ForwardedHeadersTrustedIPs` plus header-present path accepts spoofed client IPs today.
