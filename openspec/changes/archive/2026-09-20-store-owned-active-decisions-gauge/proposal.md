## Why

Stream and alone `active_decisions` is a second copy of every Ip, header, and Range store key on `MetricsReporter`. Origin is already on DecisionStore. At large IP sets that forget map is RSS, and memory expiry / Redis overwrite never adjust the gauge.

## What Changes

- DecisionStore owns the compact `{originID uint16, family} → int64` group-by, updated inside PutMany/DeleteMany (memory under the same `mu` as `putSlot` / `deleteTickLocked`; Redis MGET previous `KindOriginString` then intern the origin name in-process). Memory `PublishTick` expiry decrements swept slots.
- `Open` / `NewMemory` / `NewRedis` set `countActive` from `crowdsecMode` (true only for stream/alone). Live/none Put MUST NOT increment.
- Range is omitted from the gauge (not `ApplyRangeBatch`, not Peek). Remove dest `remember`/`forget` of Ip, header, and `range:` keys in the same change.
- MetricsReporter drops `activeDecisionSlots` and `activeDecisionsByOriginIPType`. `reportMetrics` snapshots store `ActiveCounts` and emits origin names via `OriginName` at POST. Dropped window + processed atomics stay on the reporter. Omit `active_decisions` unless stream/alone.
- Do not store `usageMetricKey` or LAPI item JSON in decisionstore. Do not add a Go engine interface. Keep intern overflow origin id 0 / empty `OriginName`.
- Keep existing debt `knowledge/debt/2026-09-20-range-active-decisions-forget.md` (Range exact-CIDR forget / `ApplyRangeBatch` displacements stay later).
- Usage packets `knowledge/devdocs/core_plugin_lapi_usage-metrics.md` and `knowledge/devdocs/core_plugin_decisionstore.md` update when implement lands (dest still matches until apply). Do not silent-rename those files.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_lapi_usage-metrics`: drop the per-slot forget map; reporter snapshots store counts at POST; Range omitted from `active_decisions` until debt; overflow id 0 still empty `OriginName`.
- `core_plugin_decisionstore_store`: store owns the compact origin×family group-by; `countActive` at Open/New; PutMany/DeleteMany/memory PublishTick expiry adjust counts; Redis previous origin via MGET + in-process intern; `ActiveCounts` snapshot; no engine interface.

## Impact

- `pkg/decisionstore` (`store.go`, `memory.go`, `redis.go`, Open/New + `ActiveCounts`)
- `pkg/lapi/decisionstore.go` (mode → `countActive`)
- `pkg/lapi/client_metrics.go` (drop both maps; snapshot at POST)
- `pkg/lapi/client_stream.go`, `pkg/lapi/client_decisions.go` (remove remember/forget)
- Tests that call remember/forget (`pkg/lapi/zzz_metrics_test.go`, `pkg/lapi/zzz_origin_intern_test.go`)
- OpenSpec folds only the two specs above; do not add a stream-apply spec folder (stream-apply does not require remember)
- Usage packets when implement lands
- No **BREAKING** public JSON/YAML keys
- Out of scope: Range exact-CIDR forget / `ApplyRangeBatch` displacements; querying `RangeMembership.Remediation` / Helper `Contains`; Redis intern table; replacing tick maps; counting live/none memo; N decisions per cache key; new public config; patching vendor iplookup
