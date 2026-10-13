## Context

See proposal.md — Why. Today `GetRemoteIP` returns only a string. `ServeHTTP` then calls `ip.Family(remoteIP)`, `Checker.Contains(remoteIP)`, and `RangeMembership.Remediation(remoteIP)`, each parsing again. `ContainsIP` and `Helper.IsContained` already take `net.IP`. `IncProcessed` / `IncDropped` already take `ip_type`. Client address owner is `GetRemoteIP` (`devstate/explore.md`).

## Goals / Non-Goals

**Goals:**
- Parse the chosen client address once on the request path.
- Trusted-client, Range membership, and usage-metrics `ip_type` all use that `net.IP`.
- Keep the remoteIP string for cache keys, LAPI live lookup, AppSec, logs, and ban template `ClientIP`.

**Non-Goals:**
- Caching only the family string while Contains + Range still parse.
- Parsing `RemoteAddr` on the connection or metrics path.
- Changing Range-index Redis shape, plugin origin labels, or expanding CIDRs to hosts.
- A new address type beside `net.IP`.
- Threading `net.IP` through `handleBanServeHTTP` / `handleNextServeHTTP`.
- Changing fail-closed origin names.

## Decisions

1. **GetRemoteIP returns `(string, net.IP, error)`.** The XFF walk parses each hop once (`parseIP` then `ContainsIP`) and keeps the winning hop’s `net.IP`. RemoteAddr fallback: `SplitHostPort` then `parseIP`. Tests still assert the same string. Alternative: parse only in ServeHTTP after the string return — rejected; the walk already had the hop’s `net.IP`.

2. **Nil parsed after successful GetRemoteIP is trustipfail.** `ContainsIP(nil)` is false with no error. Today `Contains(string)` errors on unparseable → `plugin:tech_trustipfail`. ServeHTTP fail-closes the same way when parsed is nil. `ContainsIP` only when parsed is non-nil.

3. **`RangeMembership.Remediation` takes `net.IP`.** `LookupCachedRemediation` keeps the remoteIP string for cache keys and passes the parsed IP into membership. Existing tests parse then call `Remediation`. Alternative: a sibling method — extra API without a second job.

4. **`ipType` string is computed once in ServeHTTP** from `To4()` (nil → empty). `recordProcessed` / `recordDropped` take `ipType`. Handlers that call `recordDropped` take that string, not `net.IP`. `Family` stays for decision values / `FamilyOfHostOrCIDR`.

5. **Identity:** reuse GetRemoteIP output. Do not re-parse the chosen string for trust, Range, or request-path `ip_type`. Do not parse `RemoteAddr` again.

## Risks / Trade-offs

- [ContainsIP(nil) changes fail-closed] → explicit nil check to `trustipfail` before ContainsIP.
- [GetRemoteIP signature churn] → tests keep asserting the string; extra return is the parsed IP.
- [Threading ipType through ban/next] → extra string param, not a second parse and not `net.IP` on those paths.

## Migration Plan

Plugin version bump. No YAML keys. Rollback is the previous tag (request path parses the string again).

## Open Questions

None. Assumed proceed policies live on `devstate/explore.md`.
