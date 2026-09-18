## Why

Inserting an IPv4-mapped CIDR such as `::ffff:0:0/96` panics in the radix walk: `To4()` classifies the network as IPv4, then `insert` walks `ones=96` from bit 96 of a 16-byte IP and reads past the last byte. That abort is not an error, so Traefik `ValidateParams` and Range-index rebuild crash the process.

## What Changes

- Remap a parseable IPv4-mapped CIDR (`To4()` non-nil and mask `bits==128`) to IPv4 prefix `ones-96` and insert it on the IPv4 root. Do not panic. Do not reject. Do not walk `ones` from bit 0 on the IPv6 root.
- After a successful insert, membership matches `net.IPNet.Contains` (IPv4 and IPv4-mapped hit; native IPv6 miss).
- Config validate stays an error path only for real parse failures; a mapped CIDR no longer aborts the process.
- Add the three hunt-named regressions plus Contains-equivalent membership after insert.
- **Not BREAKING.** Native IPv4 and IPv6 CIDRs stay as they are.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_ip_radix-lookup`: IPv4-mapped CIDR insert remaps to the IPv4 prefix Go `Contains` uses, and membership follows that result.

## Impact

- `pkg/iplookup/iplookup.go` (`insert` remap; `contains` stays on the 32-bit v4 walk)
- `pkg/iplookup/zzz_iplookup_test.go` (`TestHunt_IPv4MappedSlash96DoesNotPanic`)
- `pkg/ip/zzz_checker_test.go` (`TestHunt_NewCheckerIPv4MappedSlash96`)
- `pkg/decisionscope/zzz_rangemembership_test.go` (`TestHunt_MembershipIPv4MappedCIDRDoesNotPanic`)
- `openspec/specs/core_plugin_ip_radix-lookup/spec.md`
- Usage gotcha on `knowledge/devdocs/core_plugin_ip.md` waits for apply
