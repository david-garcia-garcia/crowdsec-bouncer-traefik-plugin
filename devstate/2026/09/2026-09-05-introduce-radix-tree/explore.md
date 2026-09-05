# Explore
IssueKey: 2026-09-05-introduce-radix-tree

## Concepts

**Trusted-IP Checker**:
`pkg/ip.Checker` built from `ForwardedHeadersTrustedIPs` and `ClientTrustedIPs`. `Contains` / `ContainsIP` answer whether an address is in that pool. Used at request time for forwarded-hop stripping (`PoolStrategy`) and client bypass (`ServeHTTP` `isTrusted`).

**IP lookup helper**:
In-tree copy of traefik-geoblock `pkg/iplookup`: a binary radix tree of CIDRs. Insert at construction; `IsContained` is O(32) IPv4 / O(128) IPv6 and returns longest-prefix length. Membership only — no associated remediation.

**Range index**:
Cache blob `range-index` of `cidr=remediation` lines. `MatchRangeFromIndex` walks lines and calls `ip.InNetwork`. Out of scope for the tree this change.

**Client IP owner**:
`pkg/ip.GetRemoteIP` (via `serverPoolStrategy` / forwarded header). Decision matching and trusted-client checks consume that string. The radix helper does not parse `RemoteAddr`.

```
NewChecker(CIDRs + bare IPs)
        │
        ▼
  iplookup.Helper.AddCIDR  (bare IP → /32 or /128)
        │
        ▼
ContainsIP ──► Helper.IsContained ──► bool (ignore prefixLen)

MatchRangeFromIndex ──► ip.InNetwork  (unchanged, linear)
```

## Decisions

- Copy geoblock `iplookup` into `pkg/iplookup` (Yaegi subpackage, no new `go.mod` require). Rename exported type to `Helper` so the call site is `iplookup.Helper`, not `IpLookupHelper`.
- Wire only `pkg/ip.Checker` onto the helper. Drop the dual `authorizedIPs` / `authorizedIPsNet` slices. Convert a bare IP to `/32` (IPv4) or `/128` (IPv6) before `AddCIDR`.
- Checker stays boolean any-match: use `IsContained` found flag, ignore prefix length.
- Do not add mutexes: `NewChecker` fills the tree; request path only reads.
- Do not add per-CIDR values on nodes (Range will need that later; not this change).
- Keep `InNetwork` for single-network Range lines.
- Port geoblock tests into `pkg/iplookup` under this module’s names; add Checker tests that today do not exist (`go test ./pkg/ip/` only covers `InNetwork`).
- Spec host (propose): new leaf `core_plugin_ip_radix-lookup` (component `ip` under existing domain `plugin`).
- Usage packet for `pkg/ip` / `pkg/iplookup` is missing; produce in propose or devdocsimpact, not a glossary here.

## Open questions

- Q: Who already owns the client address this lookup classifies?
  Decision: resolved — `pkg/ip.GetRemoteIP` owns the client IP string. `Checker` owns trusted-pool membership of that string. `iplookup.Helper` owns CIDR-set containment only. Do not parse `RemoteAddr` in the helper.
  By: explore

- Q: Package path and exported names for the copied helper?
  Decision: assumed — `pkg/iplookup`, type `Helper`, constructors `NewHelper` / `NewEmptyHelper`, methods `AddCIDR`, `IsContained`, `Count`. Package name supplies “IP lookup”; do not keep geoblock `IpLookupHelper`.
  By: explore

- Q: How do bare trusted IPs enter a CIDR-only tree?
  Decision: assumed — `NewChecker` formats a parsed IPv4 as `ip/32` and IPv6 as `ip/128`, then `AddCIDR`. Equivalent to today’s exact `Equal` list.
  By: explore

- Q: Integrate the tree into Range remediation in this change?
  Decision: resolved — no. Caller forbade it. `MatchRangeFromIndex` stays linear. Follow-up on `issues.md`.
  By: explore

- Q: Copy geoblock files verbatim or adapt names/comments to this module?
  Decision: assumed — adapt (Helper names, this module import path, Apache-2.0 header plus a one-line source cite to traefik-geoblock@0c2f46da). Keep the bit-walk algorithm and tests.
  By: explore

- Q: Which other lookup sites besides Checker?
  Decision: assumed — none in this change. `validateParamsIPs` already constructs `NewChecker` (gets the tree for free). Mock LAPI and Range stay linear.
  By: explore

## Evidence

- `go test ./pkg/ip/ -count=1` passed (2026-09-05, worktree). Covers `InNetwork` only; no Checker test files.
- `ContainsIP` is two for-loops over slices. Path: `pkg/ip/ip.go`.
- Geoblock helper is membership + longest prefix. Path: `knowledge/research/ext_traefik-geoblock_iplookup/notes.md`.
- Yaegi loads `pkg/` subpackages. Path: `knowledge/research/ext_traefik_plugins_yaegi-constructor/notes.md` (Subpackages).
- Range Avoid radix. Path: `knowledge/devdocs/core_plugin_decisionscope.md`.
