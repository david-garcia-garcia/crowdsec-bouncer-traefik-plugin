## Context

See proposal.md — Why. `ApplyRangeBatch` upserts any non-empty trim. `MembershipFromIndex` calls `iplookup.Helper.AddCIDR`, which is `net.ParseCIDR` only. A stored bare IP never enters the tree. `storedMatchingPrefix` also `ParseCIDR`s the stored key. Trusted-pool `hostCIDR` already maps `net.IP` to `/32` or `/128` (`To4` first). Client IP stays `pkg/ip.GetRemoteIP`.

## Goals / Non-Goals

**Goals:**
- A parseable Range host remediates that address as `/32` or `/128`.
- Delete of the original LAPI spelling still drops the line.
- Already-stored Redis bare keys still match after hydrate.
- Origin suffix on a rewritten line still returns.

**Non-Goals:**
- Changing `NewChecker` or trusted-pool outcomes.
- Teaching `Helper.AddCIDR` to accept a bare IP.
- Equivalent-CIDR spelling (`10.1.2.0/8` vs `10.0.0.0/8`).
- live/none `?ip=` expansion.
- Stream `rememberActiveDecision("range:"+value)` key rewrite.

## Decisions

1. **Export `pkg/ip.HostCIDR`.** Same body as today's unexported `hostCIDR`. `NewChecker` calls the exported name. Alternative: duplicate four lines in `decisionscope` — rejected; one owner. Alternative: widen `AddCIDR` — rejected; Helper stays CIDR-only.

2. **Canonicalize at upsert, remove, and membership.** `net.ParseIP` on the trimmed value → `HostCIDR`; otherwise leave the string. Membership expand covers old Redis `192.0.2.1=t` lines and keeps `storedByCIDR` ParseCIDR-able. Alternative: membership-only — rejected; delete of a rewritten blob would miss the original spelling unless remove expands too.

3. **Do not rewrite stream `range:` keys.** Index and membership own the prefix. Alternative: key by `/32` — out of scope.

4. **Identity:** reuse `GetRemoteIP` for the client. Do not parse `RemoteAddr` for Range match.

## Risks / Trade-offs

- [Old blob `192.0.2.1=t` plus new write `192.0.2.1/32=t`] → two lines until the next delete. Accepted; equivalent-CIDR is another ticket. Membership expand still remediates.
- [IPv4-mapped bare IP] → `HostCIDR` uses `To4` first (`/32`). Same as the trusted pool. IPv4-mapped CIDR insert panic is out of scope.
- [Unparseable value] → still skipped. `not-a-cidr` test stays.

## Migration Plan

Plugin version bump. No new YAML keys. Next stream tick rewrites a bare host to `/32` or `/128`. Old Redis lines still match via membership expand. Rollback is the previous tag (bare hosts ignored again).

## Open Questions

None. Assumed proceed policies live on `devstate/explore.md`.
