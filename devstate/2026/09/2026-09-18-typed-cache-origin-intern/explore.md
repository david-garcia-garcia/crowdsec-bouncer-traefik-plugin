# Explore
IssueKey: 2026-09-18-typed-cache-origin-intern

## Concepts

Dest still stores every stream/alone metrics origin as a string on the cache value (`kind` + U+001F + origin) and again on `activeDecisionSlots`. Closed PR 99 packed that inside `pkg/cache`. That codec is the wrong domain: cache is a typed bag, not a remediation owner.

```
  stream write (memory)                    request allow path
  ┌─────────────────────┐                  ┌─────────────────────┐
  │ DecisionStore intern│                  │ GetInt(ip)          │
  │ name → uint16       │                  │  hit packed word    │
  │ pack kind|id<<8     │                  │  miss → Get string  │
  │ cache.SetInt        │                  │ no OriginName call  │
  └─────────────────────┘                  └─────────────────────┘
           │                                        │
           │ overflow / Redis / live                │ drop only
           ▼                                        ▼
  leftover RemediationWithOrigin           OriginName(id) → IncDropped
  (decisionscope string, cache.Set)
```

**Typed bag.** `pkg/cache` keeps string `Set`/`Get`/`GetMany`/`Delete`/`Acquire`. Add `SetInt`/`GetInt` (`uint32`). Memory `ttl_map.Heap.Set` already takes `interface{}` (`vendor/github.com/leprosus/golang-ttl-map/map.go`); a machine word does not need a cache-owned remediation type. Redis Int encoding is caller-opaque. Cache MUST NOT know kind, origin, Packed, Stored, Leftover, Remediation, or range-index separators. No `SetRemediation`. No `MemoryBackend` type switch. No `\x1e`.

**Intern + pack on DecisionStore only.** Append-only name→`uint16`, lock-free `OriginName`. Pack word: `uint32(kind[0]) | uint32(id)<<8`. Table is a field on the reclaim `DecisionStore`, not a package var, not shared across store keys. Intern stays off `lapi.Client` except thin forwards if tests need them. Do not extract stream/live/metrics packages.

**Leftover string path.** Overflow, live/none, and Redis keep `RemediationWithOrigin` strings. Those helpers leave `pkg/cache` (today `pkg/cache/remediation.go`). `decisionscope` already owns `BannedValue` / `CaptchaValue` / `NoBannedValue` and range-index lines.

**Range-index.** `decisionscope` owns line encoding (letter or letter+id as a string). The blob uses `Set`, never `SetInt`. Membership still hydrates from that string.

**Lookup.** `GetInt` for packed memory IPs; on miss or leftover, `Get` string. Resolve origin name from the store table only on drop. No second lock on the allow-path `GetInt`.

**Slots.** Compact `activeDecisionSlots` to `originID` + family. Keep the slot map (per-slot forget). Gauge POST still emits origin names via `OriginName`.

**Identity.** Client address stays `pkg/ip.GetRemoteIP` → `clientRequest.remoteIP`. This ticket does not reconstruct Host, user, tenant, or trust hop.

**Reclaim.** DecisionStore is already a reclaim value (`std_go_reclaim` / `core_cache_client`). Intern rides that incarnation. Do not add `sync.Once` or package globals.

**Usage docs today.** `knowledge/devdocs/core_cache_client.md` says payloads are opaque strings and names `cache.RemediationWithOrigin`. `core_plugin_lapi_usage-metrics.md` persists origin via that helper. `core_plugin_decisionscope.md` documents letter + U+001F + origin on Ip/header/Range-index. After apply those packets must drop the cache-owned codec and document typed get/set plus store intern.

**Specs that will move.** `core_cache_client_decision-store` still says “opaque strings only.” `core_plugin_decisions_scopes` “Remediation cache values may carry origin” is the leftover string contract. `core_plugin_lapi_usage-metrics` does not mention slot compactness. No research write: vendored `ttl_map` and SimpleRedis (`Get`/`Set` `[]byte`, `Incr` exists, no Int helper) answer the third-party facts.

## Decisions

- Cache stays a typed bag. Packed word and leftover string live outside `pkg/cache`.
- Intern table lives on `DecisionStore`. Client only thin-forwards if tests cannot reach the store.
- Leftover helpers move to `decisionscope` (same owner as letters and range-index).
- Memory stream/alone Ip and header writes pack + `SetInt` when intern succeeds.
- Redis, live/none, and intern overflow write leftover strings via `Set`.
- Range-index always `Set`. Packed memory line is letter + decimal intern id (no U+001F). Leftover line stays letter + U+001F + origin name.
- Lookup tries `GetInt` then `Get`. `OriginName` only when the winning kind is remediating.
- `activeDecisionSlots` keeps the map; values become `originID` + family.
- Do not reopen PR 99. Do not copy `wt-modsec-2026-09-18-pack-decision-origin`.
- Do not extract stream/live/metrics packages.
- Do not add public config.
- RSS at ~400K IPs is not reproduced this run; packing is the requested RSS path.

## Open questions

- Q: Who already owns the client address this change would otherwise reconstruct?
  Decision: resolved — `pkg/ip.GetRemoteIP` owns the address; `clientRequest.remoteIP` is the request-path Ip key. This change reuses that output. It does not parse `RemoteAddr` or walk forwarded hops.
  By: explore

- Q: How does `GetInt` miss vs leftover string get distinguished without a cache-owned Packed/Leftover type?
  Decision: assumed — `GetInt` type-asserts a memory `uint32` or parses the Redis Int encoding; any other stored value (including a leftover string) is `CacheMiss`. Caller then `Get`s the string. Cache does not name leftover.
  By: explore

- Q: What is the Redis Int wire form?
  Decision: assumed — decimal ASCII of the `uint32` through existing SimpleRedis `Set`/`Get` `[]byte`. Callers treat it as opaque. Stream/alone Redis writers still use leftover strings (no Redis intern table).
  By: explore

- Q: Where do leftover `RemediationWithOrigin` helpers live after they leave `pkg/cache`?
  Decision: assumed — `pkg/decisionscope` (letters, `IsActiveRemediation`, `PreferRemediation`, range-index). Delete `pkg/cache/remediation.go`.
  By: explore

- Q: What is the packed range-index line spelling?
  Decision: assumed — first letter plus decimal intern id (`t12`). Leftover stays letter + U+001F + origin name. Bare letter still matches. No `\x1e`.
  By: explore

- Q: When intern overflows `uint16`, what happens?
  Decision: assumed — that origin stays leftover strings for cache values and slot origin names stay the leftover string until a later intern would fit; do not wrap the id space.
  By: explore

- Q: Does lookup take DecisionStore (to resolve origin) or only `*cache.Client`?
  Decision: assumed — lookup returns kind plus leftover origin or packed id; bouncer/metrics call `DecisionStore.OriginName` only on drop. Lookup itself does not lock intern. Allow-path `GetInt` has no second lock.
  By: explore

- Q: Was ~400K-IP RSS measured on dest?
  Decision: assumed — not reproduced this prepare; implement packing without a 400K probe.
  By: explore
