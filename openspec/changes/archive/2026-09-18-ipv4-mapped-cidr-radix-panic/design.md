## Context

`insert` treats `To4() != nil` as IPv4, maps the address to 16 bytes, and walks `prefixLen` bits from bit 96. `ParseCIDR("::ffff:0:0/96")` keeps `ones=96` and a 128-bit mask, so the walk leaves the 16-byte IP. `contains` already caps the IPv4 walk at 32 bits. Go `IPNet.Contains` does not walk 96 bits: `networkNumberAndMask` keeps the 4-byte `To4()` network and mask `m[12:]`, so a mapped `/96` is IPv4 `/0`. Finding: `knowledge/research/std_go_net_ipv4-mapped-cidr/`. See proposal.md for motivation.

## Goals / Non-Goals

**Goals:**
- Stop the panic at `insert`, not with recover at `NewChecker` / `MembershipFromIndex`.
- Remap so membership equals `Contains`.
- Keep `contains` on the existing `To4()` / 32-bit v4 walk.

**Non-Goals:**
- Reject a parseable mapped CIDR at `AddCIDR`.
- Walk `ones` from bit 0 on the v6 root.
- Rewrite range-index keys or `storedMatchingPrefix`.
- Change `GetRemoteIP`, forwarded-header policy, `InNetwork`, geoblock, or mapped prefixes that `ParseCIDR` already turns into native IPv6 (`::ffff:192.0.2.0/24` → `::/24`).

## Decisions

1. Remap only when `To4()` is non-nil and mask `bits==128`. Prefix length becomes `ones-96`. Walk the v4 root from bit 96 for that remapped length. Store the remapped length on the node. Native IPv4 (`bits==32`) and native IPv6 (`To4()` nil) stay as written.
   Alternative considered: reject at `AddCIDR`. Rejected because validate would fail a parseable Go CIDR and Range would skip a ban Go treats as a real IPv4 network.
   Alternative considered: insert on the v6 root from bit 0. Rejected because every IPv4 query is `To4()` and would miss.

2. `contains` is unchanged. After remap, a `/96` is a v4 `/0` endpoint, so the existing 32-bit v4 walk matches IPv4 and IPv4-mapped queries and misses native IPv6.

3. Hunt tests keep the ticket names in the existing `zzz_` files: `TestHunt_IPv4MappedSlash96DoesNotPanic`, `TestHunt_NewCheckerIPv4MappedSlash96`, `TestHunt_MembershipIPv4MappedCIDRDoesNotPanic`. Assert no panic and Contains-equivalent membership.

4. `storedMatchingPrefix` is unchanged. Node `prefixLen` is IPv4 (`0` for `/96`) while the stored Range key still has `ones=96`. The existing fallback already returns a containing CIDR of that kind when `ones != prefixLen`.

## Risks / Trade-offs

- [Risk] A Range blob can store both `0.0.0.0/0` and `::ffff:0:0/96` as two keys that occupy the same v4 `/0` endpoint. → Mitigation: `storedMatchingPrefix` already falls back to any containing CIDR of that kind. Do not rewrite keys in this change.
- [Risk] Remap `ones-96` is negative if `ones < 96` while `To4()` is still non-nil. → Mitigation: a mapped prefix shorter than `/96` masks away `0xff 0xff`, so `To4()` is nil and this branch does not run (research probe: `::ffff:192.0.2.0/24` → `::/24`). Guard `ones >= 96` if implement wants a belt-and-suspenders check; do not invent a new reject path.

## Migration Plan

No config or blob migration. Existing native CIDRs keep the same insert. Operators who already listed a mapped CIDR stop crashing on validate and Range rebuild.

## Open Questions

None — ticket decisions stand.
