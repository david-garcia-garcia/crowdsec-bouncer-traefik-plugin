## Why

Stream and live already receive LAPI `decision.Scenario`. `MetricsOrigin` keeps it only for `lists` (`lists:<name>`), then the packed memory word drops it. Per-scenario usage metrics will need that raw name later. Store it on the in-memory decision now without sending a `scenario` label.

## What Changes

- Add `decisionstore.Decision.Scenario` (zero value is empty intern id 0). `streamPutItem` copies LAPI `item.Scenario`. Unexported `liveResult` carries the raw scenario so `memoLive` can Put it. Origin on that struct stays `MetricsOrigin`.
- Two intern tables on `DecisionStore`: origins stay folded `MetricsOrigin` (including `lists:<name>`); scenarios intern the raw LAPI scenario. Same `pkg/intern.Table` type (`uint16`, empty name id 0, overflow `0, false` at 65535). Not shared across reclaim keys. The metrics reporter does not own a table. Lists intern twice (`lists:firehol_level1` and `firehol_level1`).
- Re-lay the memory `uint32` to 2-bit kind enum (0 empty / 1 `t` / 2 `c` / 3 `f`) + 12-bit origin + 2-bit family + 16-bit scenario id. `LiveSlot` stays `{uint32, int32}` (8 bytes). Saturate origin at `packWord` (id `> 4095` → pack 0). `unpackWord` still returns ASCII `t`/`c`/`f`.
- Overflow loses the name, not the decision. Origin overflow Warn stays `decisionstore:intern overflow`. Scenario table overflow gets a distinct Warn. Id 0 is empty-name and overflow.
- Redis and the range blob stay `KindOriginString` (kind letter + folded origin). Intern ids stay process-local. `LookupRemediation`, `IncDropped`, `usageMetricKey`, and the no-`scenario`-label contract stay. `ActiveCounts` stays origin×family with extractors updated for the new bit layout.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_decisionstore_store`: DecisionStore owns two intern tables; memory word is 2+12+2+16; `Decision.Scenario` carries the raw LAPI name; lookup still returns kind + origin + origin id; `LiveSlot` stays 8 bytes.
- `core_plugin_lapi_usage-metrics`: interning the raw scenario MUST NOT add a `scenario` item label; reporter still owns no intern table; lists origin stays `lists:` plus scenario.

## Impact

- `pkg/decisionstore/pack.go` — `packWord` / `unpackWord` / `packedOriginID` / `packedFamily`
- `pkg/decisionstore/memory.go` — intern origin and scenario at pack; origin saturate Warn; scenario overflow Warn
- `pkg/decisionstore/store.go` — second `intern.Table`; `NewMemory` / `NewRedis`
- `pkg/decisionstore/decision.go` — `Scenario` field
- `pkg/intern/table.go` — unchanged type (`uint16` max 65535); no 12-bit saturate inside `ID`
- `pkg/lapi/client_decisions.go` — `streamPutItem` / `liveResult` / `memoLive`
- `pkg/decisionstore/activecount.go` — bit extractors only
- Tests: `pkg/decisionstore/zzz_pack_test.go`, `zzz_memory_test.go`, `zzz_activecount_bench_test.go`, `zzz_lookup_test.go`, `pkg/lapi` intern/metrics tests
- No **BREAKING** public JSON/YAML keys
- Out of scope: sending a `scenario` usage-metrics label; rewriting `origin` to `crowdsec:<scenario>`; widening Redis / range encoding; multi-decision-per-slot; a side field on `LiveSlot`; growing `LookupRemediation` with a scenario id
