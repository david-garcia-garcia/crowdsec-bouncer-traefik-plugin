# Requirement
IssueKey: 2026-09-18-ipv4-mapped-cidr-radix-panic

## Problem
On dest `fad36a12`, inserting an IPv4-mapped CIDR such as `::ffff:0:0/96` panics inside the radix walk. `net.IP.To4()` classifies the network as IPv4, then `insert` walks `prefixLen` (96) starting at bit 96 of a 16-byte IP, so `ip[bytePos]` goes past index 15. That abort is not an error: Traefik plugin validate and Range-index rebuild crash the process. Ticket hunt names `TestHunt_IPv4MappedSlash96DoesNotPanic`, `TestHunt_NewCheckerIPv4MappedSlash96`, `TestHunt_MembershipIPv4MappedCIDRDoesNotPanic` are not in this tree.

## Current (code)
- `insert` sets `isIPv4 := ip.To4() != nil`, then `ip = ip.To4().To16()` and `bitStart = 96`, then walks `i := 0; i < prefixLen`. For `::ffff:0:0/96`, `ParseCIDR` succeeds, `To4()` is non-nil, `prefixLen` is 96, and `actualBitPos` reaches 128 (`pkg/iplookup/iplookup.go`).
- `contains` uses the same `To4()` / bit-96 split and a 32-bit max walk for anything `To4()` accepts (`pkg/iplookup/iplookup.go`).
- `AddCIDR` / `NewHelper` only return on `net.ParseCIDR` failure; they call `insert` with no recover (`pkg/iplookup/iplookup.go`).
- `ip.NewChecker` trims each entry, converts a bare IP via `hostCIDR`, otherwise `AddCIDR` as written (`pkg/ip/checker.go`).
- `validateParamsIPs` builds that Checker for `BouncerForwardedTrustedIPs` and `BouncerClientTrustedIPs`. A parseable IPv4-mapped CIDR therefore panics at `ValidateParams` (`pkg/configuration/configuration.go`).
- `MembershipFromIndex` skips `AddCIDR` errors and invalid lines; a parseable IPv4-mapped range still reaches `insert` and panics (`pkg/decisionscope/rangemembership.go`).
- Existing helper tests cover v4, v6, mixed, `/0` family split, invalid prefix, overlap; none insert `::ffff:0:0/96` (`pkg/iplookup/zzz_iplookup_test.go`).
- Spec already requires trusted-pool membership to follow `net.IPNet.Contains` family rules for `0.0.0.0/0` vs `::/0` (`openspec/specs/core_plugin_ip_radix-lookup/spec.md`).
- Hunt tests named in the ticket: not found.

## Desired
- Insert of an IPv4-mapped CIDR must not panic. Ticket allows either: store it as IPv6 (walk from bit 0 for the real prefix) or reject with an error.
- After a successful insert, membership must match `net.IPNet.Contains`.
- Config validate must fail cleanly (error), not crash Traefik.
- Add regression tests, including the three hunt names (or equivalent `zzz_` coverage of helper, NewChecker, and MembershipFromIndex).
- Bound the change to this defect only.

## Affected
- `pkg/iplookup/iplookup.go` (`insert`, and `contains` if classification changes)
- `pkg/iplookup/zzz_iplookup_test.go`
- `pkg/ip/checker.go` / `pkg/ip/zzz_checker_test.go` (NewChecker surface)
- `pkg/decisionscope/rangemembership.go` / `pkg/decisionscope/zzz_rangemembership_test.go` (MembershipFromIndex surface)
- `pkg/configuration/configuration.go` (`validateParamsIPs` via NewChecker) and its tests if validate must stay non-panic
- `openspec/specs/core_plugin_ip_radix-lookup/spec.md` (propose: IPv4-mapped insert / Contains)
- `knowledge/devdocs/core_plugin_ip.md` if usage must name the IPv4-mapped rule

## Out of scope
- Upstream traefik-geoblock
- `GetRemoteIP`, forwarded-header policy, `BouncerForwardedInsecure`
- `ip.InNetwork` / `pkg/ip/network.go` unless it shares this insert panic
- Range-index blob format, ban-vs-captcha precedence, live/none LAPI `?ip=`
- Radix performance, delete API, remediation payload on Helper
- Any other CIDR or IP bug not required to stop this panic

## Unknowns
- Which allowed fix this run takes (insert-as-IPv6 vs reject-with-error). Ticket accepts either; explore decides.
- Exact `net.IPNet.Contains` outcomes for `::ffff:0:0/96` against IPv4 vs IPv4-mapped vs native IPv6 inputs (must match after a successful insert).
- Whether reject-with-error should treat the CIDR as invalid at `AddCIDR` (NewChecker / validate fail) and skip it in `MembershipFromIndex` (today skips only parse errors).

## Tensions
- Two legal fixes. Insert-as-IPv6 keeps a parseable CIDR in the tree; reject turns a parseable Go CIDR into a construction error. Spec today only names `/0` family rules, not IPv4-mapped prefixes.
- `To4()` non-nil is the family test everywhere in this helper; an IPv4-mapped `/96` is IPv6-sized yet classified IPv4.
- `MembershipFromIndex` already skips invalid lines; a panic is worse than skip, but skip-after-reject would silently drop a Range decision.
- Ticket hunt names are proven FAIL off-tree; this dest has no those tests yet.
