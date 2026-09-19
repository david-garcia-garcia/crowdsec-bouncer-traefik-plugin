## Context

See proposal.md — Why. `RangeMembership.Remediation` asks ban then captcha `IsContained`, then `storedMatchingPrefix` walks `storedByCIDR` with `net.ParseCIDR`. `radixNode` already has the winning `prefixLen`. Trusted-IP `Checker` uses the same helper as a boolean set (`AddCIDR` + `IsContained`). Client address stays `pkg/ip.GetRemoteIP`. Identity-owner Decision on explore.md: reuse that `net.IP`.

## Goals / Non-Goals

**Goals:**
- Range hit returns the stored string from the winning endpoint in O(prefix).
- Checker and `AddCIDR` / `IsContained` stay boolean.

**Non-Goals:**
- One tree for ban and captcha.
- Redis request-path, live/none hydrate, blob format, geolocation.

## Decisions

1. **New insert path, not a wider `AddCIDR`.** `AddCIDR` stays a boolean insert (empty stored string). Range hydrate calls `AddCIDRRemediation(cidr, remediation)` that parses the CIDR and stores that string on the endpoint. Alternative: optional payload on `AddCIDR` — rejected; Checker and `NewHelper` must not grow a remediation argument.

2. **New read path, not a new `IsContained` return.** `IsContained` stays `(bool, int, error)`. Range `Remediation` asks `ContainedRemediation`, which returns the stored string of the longest match (empty on miss). Alternative: add a fourth return — rejected; Checker and existing tests stay boolean.

3. **Drop `storedByCIDR` and `storedMatchingPrefix`.** Hydrate writes the string onto the node. Nothing else reads the map.

4. **Same remapped endpoint: last successful insert of that kind wins.** `0.0.0.0/0` and `::ffff:0:0/96` share v4 `/0`. Blob order is the owner. Alternative: keep the ParseCIDR fallback for `ones != prefixLen` — rejected; that is the cliff.

5. **Keep two helpers.** Ban-over-captcha stays "ask ban first." Alternative: one payload tree — rejected; a longer captcha would hide a containing ban.

## Risks / Trade-offs

- [Risk] Last-insert origin on a remapped collision differs from today's unordered map fallback. → Mitigation: same-kind only; lock with a membership test; blob format unchanged.
- [Risk] A boolean `AddCIDR` after a stored insert could clear the string on that endpoint. → Mitigation: Range hydrate uses only the stored insert; Checker never writes a payload tree.

## Migration Plan

In-process only. Next stream/alone hydrate rebuilds membership from the existing blob. No Redis rewrite. Rollback is revert; old walk returns.

## Open Questions

None. Explore Decisions stand.
