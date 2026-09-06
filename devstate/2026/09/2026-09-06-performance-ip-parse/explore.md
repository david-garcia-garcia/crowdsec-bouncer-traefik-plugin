# Explore
IssueKey: 2026-09-06-performance-ip-parse

## Concepts

**GetRemoteIP** is the owner of the client address. Today it returns only the string. Downstream `Family`, `Checker.Contains`, and `RangeMembership.Remediation` each parse that string again. `Checker.ContainsIP` and `iplookup.Helper.IsContained` already take `net.IP`. `IncProcessed` / `IncDropped` already take `ip_type`.

**Winning hop:** `PoolStrategy.getIP` already `Contains` (parse) each XFF hop. The untrusted hop’s `net.IP` is discarded; ServeHTTP parses the same string again.

**Fail-closed unparseable client:** `Contains(string)` errors on empty/invalid → `plugin:tech_trustipfail`. `ContainsIP(nil)` is false with no error (`pkg/ip/checker.go`). Switching blindly to `ContainsIP` would let an unparseable client continue as untrusted instead of fail-closed.

Usage packets already exist: `core_plugin_ip.md` (GetRemoteIP then Contains on the string; Family on the string), `core_plugin_lapi_usage-metrics.md` (`ip.Family(remoteIP)`), `core_plugin_decisionscope.md` (same snippet). Stale versus the desired parse-once path; no new Language term. `core_plugin_middleware.md` already says GetRemoteIP, not string-then-Contains.

No third-party research: this is `net.ParseIP` / `To4` on an address this plugin already chose.

```
  request
     │
     ▼
  GetRemoteIP ── string (cache, LAPI, AppSec, logs, ClientIP)
     │
     └── net.IP (once)
            │
            ├─ ContainsIP          trusted client
            ├─ Range Remediation   stream/alone
            └─ To4() → ip_type     IncProcessed / IncDropped
```

## Decisions

- Parse at GetRemoteIP / the XFF walk (keep the winning hop’s `net.IP`), not a second parse-only block that leaves Contains + Range on strings.
- Trusted-client: `ContainsIP` when parsed is non-nil. When GetRemoteIP succeeds and parsed is nil, keep today’s Contains error outcome (`plugin:tech_trustipfail`). Do not treat nil as “not trusted, continue.”
- Range: `Remediation` takes `net.IP`; `LookupCachedRemediation` passes that IP into membership. Cache keys stay the string.
- Metrics: `ip_type` from that `net.IP` (`To4() != nil` → ipv4, else ipv6, empty if nil). Put `req`, `remoteIP`, parsed `net.IP`, and `ipType` on `clientRequest`. Pass that type through ban/next/AppSec. Do not put scopes or origin on it. Do not call `ip.Family(remoteIP)` on the request path.
- `Family` / `FamilyOfHostOrCIDR` stay for decision values and tests.
- Spec delta is parse-once wiring on existing `core_plugin_ip_radix-lookup` (and lookup/Range if the string signature is specified). `core_plugin_lapi_usage-metrics` behavior unchanged; owner of the parse moves. Usage packets listed above update in apply.

## Open questions

- Q: Who already owns the client address fact on the request path?
  Decision: resolved — `pkg/ip.GetRemoteIP` owns the client string (XFF walk then RemoteAddr host). Reuse that string. The parse of that chosen address has no owner today (Family, Contains, and Range each reconstruct). This change makes GetRemoteIP (or the walk it calls) also keep the winning `net.IP`; callers MUST NOT parse the string again for trust, Range, or ip_type.
  By: explore

- Q: Should GetRemoteIP return `(string, net.IP, error)` or should ServeHTTP parse immediately after the string return?
  Decision: assumed — return `(string, net.IP, error)`. The XFF walk already parsed the winning hop in `Contains`; keep that `net.IP`. RemoteAddr fallback: `SplitHostPort` then `parseIP`. Tests still assert the same string. No new address type.
  By: explore

- Q: How do we keep `plugin:tech_trustipfail` if trusted-client uses `ContainsIP` (no parse error)?
  Decision: assumed — if GetRemoteIP returns no error and `net.IP` is nil, ServeHTTP fail-closes with `OriginPluginTechTrustIPFail` (same as today’s `Contains` error). `ContainsIP` only when parsed is non-nil.
  By: explore

- Q: `RangeMembership.Remediation` signature vs a sibling?
  Decision: assumed — change `Remediation` to take `net.IP`. Update existing string tests to `net.ParseIP` then `Remediation`. No new test suite. `LookupCachedRemediation` takes the parsed IP for the membership call; the `remoteIP` string argument stays for cache keys.
  By: explore

- Q: How does `recordDropped` get `ip_type` without `Family(remoteIP)` and without a bag of request metadata?
  Decision: assumed — compute `ipType` once in ServeHTTP from the parsed IP. Fold `req`, `remoteIP`, parsed `net.IP`, and `ipType` into `clientRequest`. Pass that type through handlers that call `recordDropped`. Scopes and origin stay off the type. `recordProcessed` / `recordDropped` still take `ipType string` from `client.ipType`.
  By: implement (chat)
