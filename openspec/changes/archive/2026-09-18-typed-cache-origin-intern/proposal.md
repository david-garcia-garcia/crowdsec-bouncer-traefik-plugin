## Why

Stream and alone store each usage-metrics origin as a string on every memory cache value and again on `activeDecisionSlots`. At large decision sets that is the RSS path. Dest still writes leftover strings and has no store-owned intern table. Closed PR 99 packed remediations inside `pkg/cache`; that domain is rejected.

## What Changes

- `pkg/cache` stays a typed bag: keep string `Set`/`Get`/`GetMany`/`Delete`/`Acquire` and add `SetInt`/`GetInt` (`uint32`). Cache MUST NOT know kind, origin, Packed, Stored, Leftover, Remediation, or range-index separators. No `SetRemediation`. No `MemoryBackend` remediation switch. No `\x1e`.
- Move leftover `RemediationWithOrigin` / `RemediationKind` / `RemediationOrigin` out of `pkg/cache` into `pkg/decisionscope`.
- Put an append-only origin intern table on `DecisionStore` (name→`uint16`, lock-free `OriginName`). Pack word is `uint32(kind[0]) | uint32(id)<<8`. Overflow, live/none, and Redis keep leftover strings. Table is not a package var and is not shared across store reclaim keys.
- Stream/alone memory Ip and header writes pack + `SetInt` when intern succeeds. Range-index stays a string blob via `Set` (`decisionscope` owns letter or letter+id encoding).
- Lookup tries `GetInt` then `Get`. Resolve origin name from the store table only on drop. No second lock on the allow-path `GetInt`.
- Compact `activeDecisionSlots` to `originID` + family. Keep the slot map. Gauge POST still emits origin names.
- Update cache usage docs: typed get/set; no remediation codec in `pkg/cache`.
- Do not extract stream/live/metrics packages. Do not reopen PR 99. No public config.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_cache_client_decision-store`: cache Client is a typed bag (`Set`/`Get` strings plus `SetInt`/`GetInt` uint32). DecisionStore owns the origin intern table and the pack word. Cache MUST NOT export remediation names or origin codecs.
- `core_plugin_decisions_scopes`: leftover letter+U+001F+origin helpers live here. Packed memory range-index lines are letter plus decimal intern id. Lookup uses `GetInt` then `Get`. Client address stays `pkg/ip.GetRemoteIP`.
- `core_plugin_lapi_usage-metrics`: `activeDecisionSlots` stores `originID` + family; forget still uses the slot map; POST origin labels are `OriginName` on drop/report.
- `core_cache_redis_utilities-client`: Redis `SetInt`/`GetInt` use existing SimpleRedis `Set`/`Get` `[]byte` as decimal ASCII of the uint32. Unparseable values are a miss.

## Impact

- `pkg/cache/cache.go` (`SetInt`/`GetInt`; memory word / Redis opaque Int)
- `pkg/cache/remediation.go` (leave cache)
- `pkg/lapi/decisionstore.go` (intern table)
- `pkg/lapi/client_decisions.go`, `pkg/lapi/client_stream.go` (pack on write; intern off Client except thin forwards)
- `pkg/decisionscope/lookup.go`, `pkg/decisionscope/range.go`, `pkg/decisionscope/rangemembership.go`, `pkg/bouncer/bouncer.go`
- `pkg/lapi/client_metrics.go` (compact slots)
- `knowledge/devdocs/core_cache_client.md` (and Redis usage if Int encoding is documented)
- Tests under `pkg/cache`, `pkg/lapi`, `pkg/decisionscope`, `pkg/bouncer`
- No **BREAKING** public JSON/YAML keys
- Out of scope: Redis intern table; replacing `ttl_map`; dropping `activeDecisionSlots`; new public config; extracting stream/live/metrics packages; reopening PR 99
