# Requirement
IssueKey: 2026-09-20-store-active-decisions-gauge

## Problem
Stream/alone `active_decisions` is a second copy of every Ip/header/Range store key on `MetricsReporter` (`activeDecisionSlots` plus `activeDecisionsByOriginIPType`). At large IP sets that map is RSS. Origin is already on DecisionStore (`LiveSlot.Word` memory, `KindOriginString` Redis).

## Current (code)
- `MetricsReporter` holds `activeDecisionSlots map[string]activeDecisionSlot` (intern `originID` + family) and `activeDecisionsByOriginIPType map[usageMetricKey]int64`. `pkg/lapi/client_metrics.go`
- `rememberActiveDecision` / `forgetActiveDecision` live on Client and reporter. Remember no-ops unless `crowdsecMode` is stream or alone. Forget has no mode gate. `pkg/lapi/client_metrics.go`
- Stream/alone Ip and header New: `rememberActiveDecision(SlotKey, origin, value)` then `PutMany`. Deleted: `forgetActiveDecision(SlotKey)` then `DeleteMany`. `pkg/lapi/client_decisions.go` `pkg/lapi/client_stream.go`
- Stream Range New: `rememberActiveDecision("range:"+cidr, …)` then `ApplyRangeBatch`. Deleted: `forgetActiveDecision("range:"+cidr)`. `pkg/lapi/client_stream.go`
- Live/none memo is `memoLive` → `Store.Put` and does not call remember/forget. `pkg/lapi/client_live.go` `pkg/lapi/client_decisions.go`
- `reportMetrics` copies `activeDecisionsByOriginIPType` into POST items (`name=active_decisions`, `unit=ip`) and resolves origin via `originName` (`Client.OriginName` → `Store.OriginName`). Dropped window + processed atomics stay on the reporter. `pkg/lapi/client_metrics.go`
- Memory `putSlot` overwrites `LiveSlot` under `mu` and does not adjust a gauge. `DeleteMany` / `deleteTickLocked` delete keys only. `PublishTick` deletes expired tick slots and does not decrement any gauge. `pkg/decisionstore/memory.go`
- Redis `PutMany` is `MSetEX` of `KindOriginString` with no prior GET. `DeleteMany` is DEL with no GET. `PublishTick` is a no-op. `getMany` / `MGet` exist for lookup only. `pkg/decisionstore/redis.go`
- Memory origin id is packed in `LiveSlot.Word` (`packWord`). Redis origin is the `KindOriginString` string; `Unpack` of a string returns `originID` 0. `pkg/decisionstore/pack.go` `pkg/decisionstore/liveslot.go`
- `OpenDecisionStore` / `Store.Open` / `NewMemory` / `NewRedis` do not take `crowdsecMode` or a count-active flag. `pkg/lapi/decisionstore.go` `pkg/decisionstore/store.go`
- Engine dispatch is `type engine struct` of funcs (Yaegi). No Go interface for the engine. `pkg/decisionstore/store.go`
- `Store.Peek` for a slot: not found.
- Spec: per-slot forget map one entry per Ip, header, or Range; intern id + family; POST via `OriginName`; overflow id 0 / empty name. `openspec/specs/core_plugin_lapi_usage-metrics/spec.md` requirement Active-decision slots store intern id and family
- Usage language: compact slot is the reporter slot map. `knowledge/devdocs/core_plugin_lapi_usage-metrics.md`
- DecisionStore spec owns intern/pack/COW/Redis; it does not own an active-record group-by. `openspec/specs/core_plugin_decisionstore_store/spec.md`
- `knowledge/debt/2026-09-20-range-active-decisions-forget.md` on dest: not found (dest has `knowledge/debt/2026-09-19-multiple-decisions-per-cache-key.md` only)
- LAPI POST shape: research packet exists. `knowledge/research/ext_crowdsec_lapi_usage-metrics/`

## Desired
- DecisionStore owns the active-record group-by: compact `{originID uint16, family} → int64`, updated inside PutMany/DeleteMany (memory: same `mu` as `putSlot` / `deleteTickLocked`; Redis: MGET previous origin then adjust in-process counts). Memory `PublishTick` expiry SHOULD decrement when a slot is swept.
- MetricsReporter MUST NOT keep `activeDecisionSlots` or `activeDecisionsByOriginIPType`. `reportMetrics` snapshots store counts and emits origin names via `OriginName` at POST. Dropped window + processed atomics stay on the reporter.
- Count only stream/alone Ip and header-scope mutations. Live/none Put memo MUST NOT increment. `OpenDecisionStore` / New sets `countActive` (or equivalent) from `crowdsecMode`; reporter still omits `active_decisions` unless stream/alone.
- Do not store `usageMetricKey` / LAPI item JSON shape in decisionstore.
- Do not add a Go interface for the engine. Store method(s) to read counts for POST are fine.
- Remove remember/forget from stream apply for Ip/header (store mutations carry the gauge). Range: do not forget/peek membership; omit Range from counts (not +1 on New with no Deleted) until debt is taken.
- Spec fold: `core_plugin_lapi_usage-metrics` (drop per-slot forget map; reporter snapshots store) and `core_plugin_decisionstore_store` (store owns the group-by). Keep intern overflow origin id 0 / empty `OriginName`.
- Land `knowledge/debt/2026-09-20-range-active-decisions-forget.md` (recreate; IssueKey `2026-09-20-store-active-decisions-gauge`) and an `issues.md` note-large row. Range exact-CIDR forget / `ApplyRangeBatch` displacements stay later.

## Affected
- `pkg/lapi/client_metrics.go`, `client_stream.go`, `client_decisions.go`, tests that call remember/forget
- `pkg/decisionstore/memory.go`, `redis.go`, `store.go` (Open/New + count snapshot)
- `pkg/lapi/decisionstore.go` (`OpenDecisionStore` / mode → countActive)
- `openspec/specs/core_plugin_lapi_usage-metrics/spec.md`, `openspec/specs/core_plugin_decisionstore_store/spec.md`
- `knowledge/devdocs/core_plugin_lapi_usage-metrics.md`
- `knowledge/debt/2026-09-20-range-active-decisions-forget.md` (create)

## Out of scope
- Range exact-CIDR forget / `ApplyRangeBatch` displacements (debt)
- Querying `RangeMembership.Remediation` / Helper `Contains` for metrics
- Redis intern table
- Replacing tick maps
- Counting live/none memo
- N decisions per cache key
- New public config
- Patching vendor iplookup

## Unknowns
- Exact Store snapshot method name (ticket allows method(s) to read counts for POST).
- Redis previous-origin parse: MGET bytes are `KindOriginString`; intern id for the compact map is not stored on Redis (Unpack string → originID 0). Implement must intern the retrieved origin name in-process without a Redis intern table.
- Whether header-scope family is `FamilyOfHostOrCIDR` on the identifier (today’s remember path) or a distinct family token.

## Tensions
- Spec requires one forget-map entry per Range record; ticket omits Range from the store-owned gauge until debt. `openspec/specs/core_plugin_lapi_usage-metrics/spec.md`
- Dest Range New still `rememberActiveDecision("range:"+cidr)` (gauge +1 with no store Peek). Ticket: do not +1 Range. `pkg/lapi/client_stream.go`
- Dest `PublishTick` expiry does not forget; ticket wants a decrement on sweep. `pkg/decisionstore/memory.go`
- Dest Redis Put/Delete do not GET previous origin; ticket wants MGET then adjust. `pkg/decisionstore/redis.go`
- Dest `Open`/`NewMemory`/`NewRedis` ignore mode; after store-owned counts, live `Put` would increment unless `countActive` is false. `pkg/decisionstore/store.go` `pkg/lapi/client_live.go`
