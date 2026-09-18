# Explore
IssueKey: 2026-09-18-pack-decision-origin

## Concepts

Stream/alone memory RSS at ~400K IP decisions is two maps, not one string field.

- **ttl_map value**: `RemediationWithOrigin` → `t` + U+001F + origin. `json.Unmarshal` does not intern; each decision allocates a fresh origin and a fresh concat.
- **activeDecisionSlots**: `map[string]usageMetricKey` (five string headers). Larger than the TTL map in the heap probe.
- **Origin dictionary**: append-only `MetricsOrigin` → uint16. Kind stays ASCII `t`/`c`/`f`/`d`. Family may be `4`/`6`.
- **Packed memory value**: kind byte + origin id in one word (or ttl_map `uint32`). Not a per-decision origin string.
- **DecisionStore table**: packed ids are cache payload. Two `lapi.Client`s that share a store must share ids. MetricsReporter is per Client and is not a reclaim object.

```
  stream write
       │
       ├─ intern(origin) → id          DecisionStore table
       ├─ memory ttl_map[ip] = pack(kind, id)
       └─ slots[ip] = {id, family}     MetricsReporter
  request
       │
       ├─ kind  = unpack (no table, no extra lock)
       └─ origin = table[id] only on drop
```

Heap probe (this explore, CAPI-like mix, 400K IPv4, same `ttl_map` + `usageMetricKey` shape): current ~113 MiB; intern-only ~96 MiB; packed + compact slots ~54 MiB.

## Decisions

- Packing is memory-backend only. Redis keeps `RemediationWithOrigin` strings. No Redis intern table.
- Origin table is append-only, session-scoped, not a package `var`.
- Do not replace ttl_map. Do not drop `activeDecisionSlots`. No public config.
- Live/none stay on the string codec; their SessionHex includes mode so they do not share this store.

## Reproduce

**reproduced.** Caller probe and this explore's heap program: 400K unique IPv4 keys + unique-per-decision origin strings + `activeDecisionSlots` → ~108–115 MiB HeapAlloc after 2× GC. Cache-only ~50–53 MiB; slots-only ~64–67 MiB. Dest code still concatenates and stores `usageMetricKey` (`pkg/cache/remediation.go`, `pkg/lapi/client_metrics.go`).

## Open questions

- Q: Who owns the origin dictionary — DecisionStore or MetricsReporter?
  Decision: resolved — DecisionStore. Packed ids are shared-cache payload; two Clients that reclaim the same store must see the same ids. MetricsReporter holds compact slots and resolves names through the store table. Reporter is not its own reclaim value.
  By: explore

- Q: How do packed memory values coexist with string `cacheInterface` and Redis full-string writes without a second lock on `Get`?
  Decision: assumed — `localCache` stores `uint32` in ttl_map `Data.Value` (`interface{}` already). Redis `set` still writes the full origin string. String `Get`/`Set` stay for Redis, the stream lease, and the `range-index` blob. Memory Ip/header slots use a type-switch accessor that shift/masks the packed word (or `stored[:1]` when the value is still a letter string). `table[id]` runs only on drop / origin resolve. Do not format a `\x1f` string on every `Get`. Do not take intern `mu` on the allow path; append-only slice is readable without a lock after the write publishes the new backing.
  By: propose

- Q: Origin-id width and overflow when `lists:<scenario>` cardinality is large?
  Decision: assumed — `uint16` (65 535 names). CAPI list cardinality is tens to hundreds. Overflow: do not intern; keep that decision on the existing `\x1f` string path and log once. Do not wrap ids.
  By: explore

- Q: Do Range `range-index` blob lines pack the same way as per-IP ttl_map values?
  Decision: assumed — yes on the memory path. `rangeUpserts` already go through `RemediationWithOrigin`; intern + pack those values before `ApplyRangeBatch`. Redis may still persist the full suffix. `RangeMembership.storedByCIDR` then holds packed (or interned) values, not 400K unique concats.
  By: explore

- Q: Does this work reconstruct client address / Host / trust hop?
  Decision: resolved — none. Reuse `IPCacheKey` / `GetRemoteIP` / `FamilyOfHostOrCIDR`. Packing does not invent identity.
  By: explore
