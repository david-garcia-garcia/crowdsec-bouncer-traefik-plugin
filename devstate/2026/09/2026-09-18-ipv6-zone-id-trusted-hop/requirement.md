# Requirement
IssueKey: 2026-09-18-ipv6-zone-id-trusted-hop

## Problem
A link-local IPv6 peer that Go writes as `fe80::1%eth0` never counts as a trusted hop. `parseIP` calls `net.ParseIP` only, which rejects the zone, so `GetRemoteIP` treats `[fe80::1%eth0]:443` as untrusted and ignores `X-Forwarded-For`.

## Current (code)
- `parseIP` is `net.ParseIP(addr)` with no zone strip. A string with `%zone` returns `parseIP:parseAddress`. `pkg/ip/checker.go`
- `Contains` parses through `parseIP`, so `Contains("fe80::1%eth0")` errors instead of testing `fe80::/10`. `pkg/ip/checker.go`
- `GetRemoteIP` uses `net.SplitHostPort` then `parseIP(remoteHost)` for the trusted-peer gate. Host `fe80::1%eth0` fails parse, `trustedPeer` stays false, forwarded headers are ignored, and the fallback `parseIP` also yields a nil `net.IP`. `pkg/ip/checker.go`
- `getIP` walks hops with the same `parseIP`; a zoned hop is treated as unparseable and returned raw with nil `net.IP`. `pkg/ip/checker.go`
- Existing GetRemoteIP cases use IPv4 peers (`10.0.0.1:443`) or catch-all IPv4/IPv6 pools. No zoned-IPv6 RemoteAddr or `Contains("fe80::1%eth0")` case. `pkg/ip/zzz_checker_test.go`
- `TestHunt_ZonedIPv6RemoteAddrIsTrustedHop` is not in dest. `not found`
- Spec and usage language for GetRemoteIP do not mention zone IDs. `openspec/specs/core_plugin_ip_radix-lookup/spec.md` `knowledge/devdocs/core_plugin_ip.md`

## Desired
- Strip the IPv6 zone so `fe80::1%eth0` is `fe80::1` before `parseIP` / `Contains` / `GetRemoteIP` pool membership, hop walk, and the yielded `net.IP`.
- `Contains("fe80::1%eth0")` against pool `fe80::/10` is true.
- `RemoteAddr` `[fe80::1%eth0]:443` with pool `fe80::/10` and `X-Forwarded-For: 203.0.113.10` returns `203.0.113.10`.
- Regression tests for those cases.
- This defect only.

## Affected
- `pkg/ip/checker.go`
- `pkg/ip/zzz_checker_test.go`
- `pkg/ip/network.go` (`InNetwork` calls `parseIP`)

## Out of scope
- #77 IP cache-key canonicalization (`IPCacheKey` / `IPLookupCacheKey`, decision-store spelling).
- `Family` / `FamilyOfHostOrCIDR` still calling `net.ParseIP` on the string (`pkg/ip/network.go`).
- Zone IDs in `NewChecker` pool entries (those still use `net.ParseIP` on the CIDR list).
- `ForwardedHeadersInsecure`, captcha, AppSec, cache, LAPI, reclaim.

## Unknowns
- Whether the GetRemoteIP **string** for a zoned RemoteAddr fallback keeps `%eth0` or becomes `fe80::1`. Ticket names only membership, hop walk, and the yielded `net.IP`.
- Whether a zoned hop in the forwarded header should return the original hop text or the stripped address.
- Hunt test source is not on dest; later phases must add in-tree regressions, not depend on that name.

## Tensions
- Ticket line `pkg/ip/checker.go:84-91` matches dest `parseIP`.
- Ticket cites `TestHunt_ZonedIPv6RemoteAddrIsTrustedHop` as proven FAIL; that name is not on dest.
- Dest already has `ForwardedHeadersInsecure`; this ticket does not change that flag.
