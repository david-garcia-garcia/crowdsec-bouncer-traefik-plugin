## 1. Store compact map and countActive

- [x] 1.1 Add `ActiveCountKey` (`OriginID uint16`, `Family string`), compact map, `countActive`, and count mutex on `Store`; `ActiveCounts()` returns a snapshot copy (no `usageMetricKey` / LAPI JSON)
- [x] 1.2 Pass `countActive` into `NewMemory` / `NewRedis` / `Open`; `lapi.OpenDecisionStore` sets it true only for stream/alone; do not add it to `StoreKey`
- [x] 1.3 Pass intern table + compact-map pointer into redis (same pattern as memory `origins`); do not add a Go engine interface

## 2. Memory and Redis gauge adjust

- [x] 2.1 Memory PutMany/DeleteMany: while holding `mu`, overwrite decrements previous packed origin+family then increments; missing delete is a no-op; prior-spelling extra DEL is not a second gauge event; `countActive` false is a no-op
- [x] 2.2 Memory PublishTick: when `now != 0`, decrement each expired counted slot before delete; `PublishTick(0)` still skip-sweep
- [x] 2.3 Redis PutMany/DeleteMany: MGET canonical `KindOriginString`, intern origin name in-process (`OriginID`), family from `FamilyOfHostOrCIDR` on the decision value; then MSetEX/DEL; do not persist intern ids; Redis PublishTick stays a no-op
- [x] 2.4 `ApplyRangeBatch` MUST NOT adjust the compact map

## 3. Reporter snapshot and stream apply

- [x] 3.1 Delete `activeDecisionSlots`, `activeDecisionsByOriginIPType`, `rememberActiveDecision`, and `forgetActiveDecision` from Client and MetricsReporter
- [x] 3.2 `reportMetrics` snapshots `ActiveCounts`, emits `OriginName` at POST (`name=active_decisions` `unit=ip`); overflow id 0 empty name; omit items unless stream/alone; failed POST restores dropped+processed only
- [x] 3.3 Remove remember/forget from stream Ip/header put/delete and from Range `"range:"+cidr` paths; Range stays on `ApplyRangeBatch` only

## 4. Tests and usage packets

- [x] 4.1 Update NewMemory/NewRedis/Open call sites and tests that used remember/forget; add store tests for Put/Delete/overwrite, live no-increment, Range omit, memory PublishTick expiry decrement, Redis previous-origin overwrite, overflow id 0
- [x] 4.2 Update `knowledge/devdocs/core_plugin_lapi_usage-metrics.md` (reporter no longer owns the gauge; compact group-by is DecisionStore) and `knowledge/devdocs/core_plugin_decisionstore.md` (store-owned counts, `ActiveCounts`, `countActive`); do not rename those files
- [x] 4.3 Keep `knowledge/debt/2026-09-20-range-active-decisions-forget.md` and the issues.md note-large row; recreate the debt file only if missing
- [x] 4.4 Run `go test ./pkg/decisionstore/... ./pkg/lapi/...`
