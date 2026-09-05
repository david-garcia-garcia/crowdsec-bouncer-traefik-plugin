## Context

See proposal.md — Why. `master` split Yaegi `New` (`plugin.go`) from `pkg/bouncer` and `pkg/crowdsecconnection`. Upstream PR 383 implemented the same matching in the root plugin package. Client IP is already owned by `pkg/ip.GetRemoteIP`. In-tree `pkg/simpleredis` already has `MGet`. Redis keys are prefixed with `IdentityHex`.

## Goals / Non-Goals

**Goals:**
- Port 383 matching onto the split packages.
- One Redis `MGET` per request for IP + header keys + `range-index`.
- Real-stack Pester for Range and a header-mapped scope.

**Non-Goals:**
- GeoIP inside this plugin.
- Radix-tree Range index.
- Merging upstream PR 368.
- Changing `.traefik.yml` `import`.

## Decisions

1. **`pkg/decisionscope` owns keys, range-index, and ban-over-captcha.** `crowdsecconnection` must not import `pkg/bouncer`. Alternative: put helpers on `cache.Client` — rejected; header normalize is not a cache job.

2. **Port `ip.InNetwork` for one CIDR.** `Checker.Contains` is the trusted-IP pool (many CIDRs, construction cost). Alternative: `NewChecker` per Range line — extra log and slice.

3. **`range-index` stays one key** (`cidr=remediation` lines, long TTL, rewrite on add/delete). Alternative: one Redis key per CIDR plus prefix-length set (PR 368) — extra GETs and a set that can evict.

4. **`GetMany` uses `MGet` on one `nextReader()`**, with `IdentityHex` prefix. Alternative: 383 looped GET — needed only for published v1.0.12.

5. **Header scopes are one public map** `decisionScopeHeaders`. Country/AS special only in value normalize. Alternative: `countryHeader` + `asnHeader` — a third custom scope would need a third key.

6. **Identity:** IP from `GetRemoteIP`; Country/AS/custom from the mapped header. Missing header skips that scope.

7. **Real e2e:** dedicated compose path with `decisionScopeHeaders` so existing tests stay header-free. `cscli --range` and `--scope`/`--value`. Extra headers on `Test-HttpRequest`. Mock `scope-headers` kept for CI speed.

## Risks / Trade-offs

- [Linear walk of `range-index`] → typical Range count is small; radix tree is follow-up.
- [Mapped headers are unauthenticated] → document: if the client can set the header, they change matching. Pair with a trusted hop.
- [Stream default `ip,range`] → send `scopes=` for every mapped header or Country/AS never arrive.
- [Yaegi extra package] → `pkg/cache` already loads; keep `New`/`CreateConfig` on root.

## Migration Plan

Deploy as a plugin version bump. Empty `decisionScopeHeaders` keeps header scopes off. Range matching turns on with no new key. Rollback: previous tag restores IP-only lookup.
