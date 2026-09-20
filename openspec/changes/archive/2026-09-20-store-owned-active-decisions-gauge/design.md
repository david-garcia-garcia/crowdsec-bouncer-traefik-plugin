## Context

See `proposal.md` — Why. Dest `MetricsReporter` holds `activeDecisionSlots` plus `activeDecisionsByOriginIPType` (`pkg/lapi/client_metrics.go`). Stream Ip/header remember then PutMany, forget then DeleteMany (`pkg/lapi/client_decisions.go`). Stream Range remember/forget `"range:"+cidr` then `ApplyRangeBatch` (`pkg/lapi/client_stream.go`). Memory `putSlot` / `deleteTickLocked` / `PublishTick` do not adjust a gauge (`pkg/decisionstore/memory.go`). Redis PutMany is MSetEX with no prior GET; DeleteMany is DEL (`pkg/decisionstore/redis.go`). `Open` / `NewMemory` / `NewRedis` ignore `crowdsecMode` (`pkg/decisionstore/store.go`, `pkg/lapi/decisionstore.go`). Engine is `type engine struct` of funcs (Yaegi). No `Store.Peek`. Identity-owner: DecisionStore intern.Table already owns origin intern; store counts; reporter POST (`devstate/explore.md`).

FindSpecHost (conductor, do not invent a third leaf):

```
verdicts:
  - { deltaId: usage-metrics-snapshot, fold, spec-id: core_plugin_lapi_usage-metrics, confidence: high, candidates: [core_plugin_lapi_usage-metrics, core_plugin_lapi_stream-apply] }
  - { deltaId: store-groupby, fold, spec-id: core_plugin_decisionstore_store, confidence: high, candidates: [core_plugin_decisionstore_store] }
```

Stream-apply remember/forget removal is implementation of usage-metrics. Dest `core_plugin_lapi_stream-apply` does not require remember. Do not add a stream-apply spec folder. Do not silent-rename `core_plugin_decisionstore.md` vs spec `core_plugin_decisionstore_store`.

## Goals / Non-Goals

**Goals:**

- Compact `{originID uint16, family} → int64` on Store, updated inside PutMany/DeleteMany and memory PublishTick expiry.
- `countActive` from `crowdsecMode` at Open/New; live/none Put MUST NOT increment.
- Reporter drops both maps; snapshots `ActiveCounts` at POST; `OriginName` at emit.
- Remove remember/forget from stream apply (Ip, header, Range). Omit Range from counts.

**Non-Goals:**

- Go engine interface; `usageMetricKey` / LAPI JSON in decisionstore; Redis intern table; `Store.Peek`; counting `ApplyRangeBatch` / Range membership; Redis TTL expiry of counts; putting `countActive` in `StoreKey`; renaming usage/spec packets.

## Decisions

1. **Compact map on Store, not on each engine.** One `map[ActiveCountKey]int64` plus `countActive bool` on `Store`. Memory and Redis hold a pointer (same pattern as memory's `origins *intern.Table`). `ActiveCounts()` is a Store method that copies under the count mutex. Alternative: engine interface with `activeCounts()` — rejected (Yaegi: funcs on `engine` struct only; ticket forbids a Go engine interface). Alternative: `if s.mem` / `if s.red` on every Store method — rejected (existing store spec).

2. **`ActiveCounts()` snapshot.** Returns a copy of `{OriginID uint16, Family string} → int64`. Do not export `usageMetricKey` or LAPI item structs from decisionstore. Reporter builds POST items in `pkg/lapi` (`name=active_decisions`, `unit=ip`, `OriginName` at emit). Overflow id 0 → empty `OriginName`. Alternative: iterator callback — unnecessary; a copy is the POST snapshot.

3. **`countActive` at create, not in StoreKey.** `Open` / `NewMemory` / `NewRedis` take `countActive` (true only for stream/alone). `lapi.OpenDecisionStore` derives it from `cfg.CrowdsecMode`. SessionHex already includes Mode, so stream/alone and live/none Open different stores. Live Open keeps `countActive` false so memo `Put` cannot increment. Do not put `countActive` in `StoreKey`. Traefik `New` ctx remains the reclaim holder; no `sync.Once`. Alternative: mode gate only on the reporter — rejected (a live Put on a counted store would drift the gauge).

4. **Memory adjusts under the same `mu` as `putSlot` / `deleteTickLocked`.** While `m.mu` is held, increment/decrement the Store map (nested count mutex is allowed; lock order is always `m.mu` then count mutex). Overwrite of an existing canonical slot decrements the previous group then increments the new. Origin id from packed `LiveSlot.Word`; family from `ip.FamilyOfHostOrCIDR` on the decision value at Put/Delete and on the slot key at PublishTick expiry (Ip keys are addresses; header keys POST empty `ip_type`, matching dest remember). Alternative: adjust after `putSlot` returns — rejected (ticket: same `mu`).

5. **Redis: MGET previous `KindOriginString`, intern in-process.** Before MSetEX/DEL of the canonical SlotKey, MGET that key. Split origin name from `KindOriginString`, then `Store.OriginID(name)` in-process (pass `origins *intern.Table` into redis like memory). Family from `FamilyOfHostOrCIDR` on the slot identifier / decision value, not from Unpack (Unpack of a string returns originID 0). Do not persist intern ids on Redis. Do not add a Redis intern table. Redis has no slot `mu` today; count mutex covers in-process adjust. Prior-spelling extra DEL is not a second gauge event (dest counted one SlotKey). Redis `PublishTick` stays a no-op. Redis TTL expiry without DeleteMany does not decrement (dest reporter never saw Redis TTL). Alternative: persist packed originID on Redis — rejected (no Redis intern table this ticket).

6. **Range omitted; strip remember/forget entirely.** `ApplyRangeBatch` MUST NOT adjust the compact map. Do not Peek membership. Do not query `RangeMembership.Remediation` / Helper `Contains`. Remove dest `rememberActiveDecision("range:"+cidr)` / `forgetActiveDecision("range:"+cidr)` and Ip/header remember/forget in the same change. Do not keep the reporter maps only for Range. Debt file already on the branch: `knowledge/debt/2026-09-20-range-active-decisions-forget.md` (IssueKey `2026-09-20-store-active-decisions-gauge`).

7. **Reporter POST is a snapshot.** Drop `activeDecisionSlots` and `activeDecisionsByOriginIPType`. Drop `rememberActiveDecision` / `forgetActiveDecision` (Client and reporter). Dropped window + processed atomics stay on the reporter. Failed POST restores dropped/processed only, not active counts (gauge). Reporter still omits `active_decisions` unless `crowdsecMode` is stream or alone. Header-scope family stays dest: `FamilyOfHostOrCIDR` on the decision value; Country/AS POST empty `ip_type`. Do not invent a `header` family token.

8. **Usage packets after apply.** Dest Language still says MetricsReporter owns the gauge. Propose does not rewrite `knowledge/devdocs/core_plugin_lapi_usage-metrics.md` or `core_plugin_decisionstore.md` (consume: dest matches until implement). Implement updates those packets when the gauge moves. Do not silent-rename them.

## Risks / Trade-offs

- **[Risk] Redis MGET of previous origin races another writer** → Mitigation: one Store incarnation per reclaim key; stream apply is single-flight per Client; remaining race is the same as dest Redis last-write-wins on the slot itself.
- **[Risk] Memory PublishTick(0) skip-sweep would skip decrements** → Mitigation: no expiry deletes on that path; counts stay aligned with slots that remain.
- **[Risk] Header family from slot key vs decision value** → Mitigation: both empty for Country/AS; Ip keys are canonical addresses. Keep dest `FamilyOfHostOrCIDR`.
- **[Trade-off] `cscli` `active_decisions` omits Range CIDRs** → Accepted; debt file. Do not fake it with LPM.
- **[Trade-off] Redis TTL expiry leaves counts high until DeleteMany/overwrite** → Same as dest reporter; out of scope.

## Migration Plan

Single deploy. No Redis key format change (`KindOriginString` stays). Memory maps and counts rebuild from the next stream apply (startup=true after restart). Rollback is revert. No public config flag.

## Open Questions

None. Proceed policies live on `devstate/explore.md`. Propose resolved snapshot method name `ActiveCounts` and compact-map location on Store.
