# Origin dictionary

## Language

**Origin dictionary**:
An append-only intern table on one DecisionStore that maps a first-seen `MetricsOrigin` string to the next `uint16` id (and the reverse). Session-scoped. Not a package `var`. Two `lapi.Client`s that reclaim the same store share ids.
_Avoid_: MetricsReporter table, package `var`, Redis intern table

**Packed memory value**:
A stream/alone memory remediation stored as one `uint32`: kind letter in the low 8 bits and origin id in the next 16. Not a per-decision origin string.
_Avoid_: `RemediationWithOrigin` concat on the memory allow path, formatting U+001F on `Get`

## Overview

Hang the table on the DecisionStore reclaim value at Open. Intern on stream/alone write. Store packed words in memory ttl_map. Resolve `table[id]` only on drop or usage-metrics POST. Redis and live/none stay on the leftover string codec.

## How to use

- Construct the table in `OpenDecisionStore` (`newOriginDictionary`). Do not put it on `MetricsReporter`. Do not use a package `var`.
- Intern with `DecisionStore.InternOrigin`. Empty origin does not consume an id. Overflow (`uint16` full) does not intern or wrap; it logs once per store and stays on the leftover string path.
- Build a slot with `DecisionStore.RemediationStored` (or `Client.remediationStored`). Memory interned → `cache.Packed`. Overflow/empty → `cache.Leftover`. Redis and live/none stay `Leftover(RemediationWithOrigin)`.
- Write with `cache.Client.SetRemediation`. Read with `GetManyStored`. Kind is `Stored.Kind()` (shift/mask or first leftover letter). Do not take intern `mu` on the allow path. Do not format a U+001F string on `Get`.
- Origin name is `OriginName(id)` or the leftover suffix. Call that only on drop / metrics POST.
- Range: intern + pack, then pass `IndexForm()` into `ApplyRangeBatch` on memory. Membership holds that form. Redis `range-index` MAY keep the U+001F suffix. Letter-only lines stay valid.

## Pattern snippet

```go
stored := store.RemediationStored(decisionscope.BannedValue, origin)
cacheClient.SetRemediation(ipKey, stored, ttl)
kind := stored.Kind()
name := store.OriginName(id) // drop / metrics only
```

## Key files

- `pkg/lapi/origindict.go`
- `pkg/lapi/decisionstore.go`
- `pkg/cache/stored.go`
- `pkg/cache/cache.go`

## Gotchas

- Packed ids are cache payload. Two Clients share ids only when they reclaim the same store.
- Redis writes the full `RemediationWithOrigin` string. No Redis intern table.
- Live/none stay on the string codec (`SessionHex` includes mode so they do not share this store).
- Packed `range-index` form is kind + U+001E + decimal id, not U+001F.
- Keep ttl_map. Do not replace it with a custom IP-as-bytes map.
