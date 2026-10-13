# Explore

## Concepts

Trusted-IP Checker and Range membership both insert through `pkg/iplookup.Helper.AddCIDR`. `insert` treats `To4() != nil` as IPv4, maps the address to 16 bytes, and walks `prefixLen` bits from bit 96. `net.ParseCIDR("::ffff:0:0/96")` succeeds with `ones=96` and `To4()` non-nil, so the walk reaches byte 16 and panics. `contains` caps the IPv4 walk at 32 bits, so lookup of a mapped address does not panic.

Go `IPNet.Contains` does not walk 96 bits. `networkNumberAndMask` keeps the 4-byte `To4()` network and the last four bytes of a 16-byte mask (`m[12:]`). A mapped `/96` is an IPv4 `/0`; `/120` is `/24`; `/128` is `/32`. Native IPv6 is a miss (`len` 16 vs 4). `IPNet.String()` already prints that IPv4 form. Finding: `knowledge/research/std_go_net_ipv4-mapped-cidr/`.

```
ParseCIDR("::ffff:0:0/96")
        │
        ▼
  IP 16-byte, To4()=0.0.0.0
  ones=96 bits=128
        │
        ├─ insert today ── walk 96 bits from bit 96 ── ip[16] panic
        │
        ├─ ticket "IPv6 from bit 0" ── v6 root ── IPv4 query still To4() ── miss
        │
        └─ remap ── IPv4 prefix ones-96 on v4 root ── Contains match
```

`validateParamsIPs` builds a Checker and discards it. `MembershipFromIndex` already skips `AddCIDR` errors. Bare `::ffff:0:0` in `NewChecker` goes through `hostCIDR` → `0.0.0.0/32` and does not panic. `GetRemoteIP` stays the client-address owner. `ip.InNetwork` uses `Contains` only.

Dest `fad36a12`. Reproduced on this tree: `AddCIDR`, `NewChecker`, and `MembershipFromIndex` panic `index out of range [16] with length 16` for `::ffff:0:0/96`. Existing helper/checker/range tests pass and do not insert that CIDR. Hunt names are still absent.

## Decisions

- Stop the panic in `insert` (cause), not with recover at `NewChecker` / `MembershipFromIndex`.
- Successful insert must match `net.IPNet.Contains`: remap a `To4()` network whose mask `bits==128` to IPv4 prefix `ones-96` (mask `[12:]`) and walk the v4 root from bit 96 for that remapped length. Store that remapped prefix length on the node.
- Do not walk `ones` from bit 0 on the v6 root. Every IPv4 query is `To4()` and would miss.
- Do not reject a parseable mapped CIDR at `AddCIDR`. Reject would fail validate (allowed) but skip a Range ban that Go treats as a real IPv4 network.
- `contains` stays on `To4()` / 32-bit v4 walk. No second tree lookup.
- Regression tests use the three hunt names in the existing `zzz_` files, plus Contains-equivalent membership after insert.
- Propose amends `core_plugin_ip_radix-lookup` for IPv4-mapped insert / Contains. Usage gotcha on `knowledge/devdocs/core_plugin_ip.md` waits for that apply.
- Bound: no `GetRemoteIP` / forwarded-header / `InNetwork` / geoblock / range-index blob rewrite. Mapped prefixes that ParseCIDR already turns into native IPv6 (`::ffff:192.0.2.0/24` → `::/24`) do not panic; leave them.

## Open questions

- Q: Which allowed fix does this run take (insert-as-IPv6 vs reject-with-error)?
  Decision: assumed — remap `To4()` + 128-bit mask to IPv4 prefix `ones-96` and insert on the v4 root so membership matches `Contains`. Do not reject. Do not walk `ones` from bit 0 on the v6 root (IPv4 queries would miss).
  By: explore

- Q: What are `net.IPNet.Contains` outcomes for `::ffff:0:0/96` against IPv4, IPv4-mapped, and native IPv6?
  Decision: resolved — measured on Go 1.25.6. `::ffff:0:0/96` contains every IPv4 and IPv4-mapped address (`192.0.2.1`, `::ffff:192.0.2.1`) and misses native IPv6 (`2001:db8::1`, `::1`, `::`). `::ffff:192.0.2.0/120` matches `192.0.2.0/24`. `String()` is already that IPv4 form.
  By: explore

- Q: Should reject-with-error treat the CIDR as invalid at `AddCIDR` (NewChecker / validate fail) and skip it in `MembershipFromIndex`?
  Decision: assumed — no. `AddCIDR` succeeds after remap. `MembershipFromIndex` keeps skip-on-parse-error only. Validate stays non-panic because insert no longer aborts.
  By: explore

- Q: Who already owns the client address this membership classifies?
  Decision: resolved — `pkg/ip.GetRemoteIP`. This change only classifies CIDR strings at insert. Do not parse `RemoteAddr` again.
  By: explore

- Q: Where do the three hunt test names live?
  Decision: assumed — `TestHunt_IPv4MappedSlash96DoesNotPanic` in `pkg/iplookup/zzz_iplookup_test.go`, `TestHunt_NewCheckerIPv4MappedSlash96` in `pkg/ip/zzz_checker_test.go`, `TestHunt_MembershipIPv4MappedCIDRDoesNotPanic` in `pkg/decisionscope/zzz_rangemembership_test.go`. Assert no panic and Contains-equivalent membership after insert.
  By: explore

- Q: What happens to mapped prefixes that ParseCIDR rewrites to native IPv6 (`::ffff:192.0.2.0/24` → `::/24`)?
  Decision: assumed — out of scope. They do not panic. Do not special-case them.
  By: explore

- Q: After remap, helper `prefixLen` is IPv4 (`0` for `/96`) while `ParseCIDR` `ones` on the stored Range key stays 96. Does `storedMatchingPrefix` need a change?
  Decision: assumed — no. Store the remapped IPv4 prefix on the node. `storedMatchingPrefix` already falls back to a containing CIDR of that kind when `ones != prefixLen`. Do not rewrite range-index keys.
  By: explore
