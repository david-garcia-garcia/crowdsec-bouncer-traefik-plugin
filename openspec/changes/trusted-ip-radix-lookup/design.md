## Context

See proposal.md — Why. `pkg/ip.Checker` today holds `[]*net.IP` plus `[]*net.IPNet` and walks both in `ContainsIP`. Yaegi already loads `pkg/` subpackages. Traefik-geoblock `iplookup` (research `ext_traefik-geoblock_iplookup`, commit `0c2f46da`) is a membership radix tree: `IsContained` returns found + longest prefix length, no associated values. Client IP remains `GetRemoteIP`.

## Goals / Non-Goals

**Goals:**
- In-tree radix helper used by Checker only.
- Same Checker public methods and config keys.
- Tests for helper + Checker (Checker has none on master).

**Non-Goals:**
- Range-index radix or per-CIDR remediation values on tree nodes.
- New `go.mod` require on traefik-geoblock.
- Changing `InNetwork`.
- Mutexes on the helper (tree is filled at `NewChecker`, then read-only).

## Decisions

1. **Package `pkg/iplookup`, type `Helper`.** Call site is `iplookup.Helper`. Alternative: keep geoblock `IpLookupHelper` — rejected; package already says IP lookup (`skill:sbs-dev-commandments:Name for the scope`).

2. **Copy/adapt the bit-walk, do not import geoblock.** Yaegi plugin module; one external require already (`golang-ttl-map`). Alternative: `require` geoblock — rejected.

3. **Checker owns one `Helper`.** Bare IPv4 → `ip/32`, IPv6 → `ip/128`, then `AddCIDR`. Drop `authorizedIPs` / `authorizedIPsNet`. Alternative: keep the exact-IP slice next to the tree — extra path for the same membership.

4. **Boolean any-match.** Use `IsContained` found flag; ignore prefixLen. Alternative: longest-prefix priority — Checker never needed it.

5. **No values on nodes.** Range would need `cidr → remediation`. Leave that for the follow-up on `issues.md`. Alternative: generic `map` payload now — out of scope.

6. **Identity:** classify `GetRemoteIP` output only.

## Risks / Trade-offs

- [Copied algorithm drifts from geoblock] → cite `traefik-geoblock@0c2f46da` in the file header; port its tests.
- [IPv4-mapped 16-byte walk bugs] → keep geoblock mixed v4/v6 and `/0` cases.
- [Range still O(n)] → accepted; caller deferred it.

## Migration Plan

Plugin version bump. Same YAML keys. Rollback is the previous tag (linear Checker).
