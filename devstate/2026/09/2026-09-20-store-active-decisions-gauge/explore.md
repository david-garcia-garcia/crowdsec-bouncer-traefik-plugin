# Explore
IssueKey: 2026-09-20-store-active-decisions-gauge
Qualify: qualified-with-gaps (continue — conductor full run)
Reproduced: yes — dest code in this worktree matches requirement Current. Not contradicted.

## Concepts

```
Dest (origin/master based, this worktree)
  Stream apply
    Ip/header New: remember(SlotKey) then PutMany
    Ip/header Deleted: forget(SlotKey) then DeleteMany
    Range New: remember("range:"+cidr) then ApplyRangeBatch
    Range Deleted: forget("range:"+cidr)
  MetricsReporter
    activeDecisionSlots: slot → {originID, family}     // RSS: one entry per key
    activeDecisionsByOriginIPType: usageMetricKey → n  // POST group-by
  DecisionStore
    memory LiveSlot.Word packs originID; Redis KindOriginString
    intern.Table on Store; OriginName / OriginID already here
    no Peek; no active-record group-by; PublishTick expiry does not count

Intended
  DecisionStore owns compact {originID, family} → int64
    PutMany / DeleteMany adjust (memory: same mu as putSlot / deleteTickLocked)
    Redis: MGET previous KindOriginString, intern name in-process, then adjust
    memory PublishTick expiry decrements
    countActive from crowdsecMode at Open/New; live/none Put does not increment
    Range omitted (not Peek, not ApplyRangeBatch)
  MetricsReporter drops both maps; reportMetrics snapshots store + OriginName at POST
  usageMetricKey / item JSON stay in pkg/lapi
```

**Reproduced dest (read, not hypothesized)**

- `MetricsReporter` holds `activeDecisionSlots` and `activeDecisionsByOriginIPType`. Remember no-ops unless `crowdsecMode` is stream or alone. Forget has no mode gate. `reportMetrics` copies the group-by map into POST items `name=active_decisions` `unit=ip` and resolves origin via `originName` (`Client.OriginName` → `Store.OriginName`). Dropped window + processed atomics stay on the reporter. `pkg/lapi/client_metrics.go`
- Stream/alone Ip and header New: `rememberActiveDecision(SlotKey, origin, value)` then `PutMany`. Deleted: `forgetActiveDecision(SlotKey)` then `DeleteMany`. `pkg/lapi/client_decisions.go`
- Stream Range New: `rememberActiveDecision("range:"+cidr, …)` then `ApplyRangeBatch`. Deleted: `forgetActiveDecision("range:"+cidr)`. `pkg/lapi/client_stream.go`
- Live/none memo is `memoLive` → `Store.Put` and does not call remember/forget. `pkg/lapi/client_live.go` `pkg/lapi/client_decisions.go`
- Memory `putSlot` overwrites `LiveSlot` under `mu` and does not adjust a gauge. `DeleteMany` / `deleteTickLocked` delete keys only. `PublishTick` deletes expired tick slots and does not decrement any gauge. `pkg/decisionstore/memory.go`
- Redis `PutMany` is `MSetEX` of `KindOriginString` with no prior GET. `DeleteMany` is DEL with no GET. `PublishTick` is a no-op. `getMany` / `MGet` exist for lookup only. `pkg/decisionstore/redis.go`
- Memory origin id is packed in `LiveSlot.Word`. Redis origin is the `KindOriginString` string; `Unpack` of a string returns `originID` 0. `pkg/decisionstore/pack.go`
- `OpenDecisionStore` / `Store.Open` / `NewMemory` / `NewRedis` do not take `crowdsecMode` or a count-active flag. Engine is `type engine struct` of funcs, not a Go interface. `pkg/lapi/decisionstore.go` `pkg/decisionstore/store.go`
- `Store.Peek` for a slot: not found.
- Spec requires one forget-map entry per Ip, header, or Range; intern id + family; POST via `OriginName`; overflow id 0 / empty name. `openspec/specs/core_plugin_lapi_usage-metrics/spec.md`
- DecisionStore spec owns intern/pack/COW/Redis; it does not own an active-record group-by. `openspec/specs/core_plugin_decisionstore_store/spec.md`
- Header-scope family on dest remember is `ip.FamilyOfHostOrCIDR(decisionValue)` (Country/AS identifiers → empty `ip_type`). `pkg/lapi/client_metrics.go` `pkg/ip/network.go`
- SessionHex includes `Mode`, so stream/alone and live/none Open different DecisionStores (`StoreKey` = `decisionstore:` + SessionHex + Redis params). Two live Clients that differ only on metrics interval still share one store. `pkg/lapi/session.go` `pkg/lapi/decisionstore.go`

**Devdocs / research consume**

- Root indexes: no `priority: always` packets. Plugin domain: usage-metrics, DecisionStore, stream-apply, middleware New, reclaim key, decision scopes. std_go reclaim. CrowdSec research: `ext_crowdsec_lapi_usage-metrics/`.
- Current usage Language is dest-accurate: `MetricsReporter` owns the gauge; **Compact decision slot** is the reporter forget map. Do not rewrite those packets in explore (dest still matches). Propose/implement/devdocsimpact update them when the gauge moves.
- Research answers LAPI POST shape (`active_decisions` / unit `ip` / labels `origin` + `ip_type`; cscli gauge; intern overflow empty origin is ours). No third-party gap. The packet’s “this worktree” appendix still names `pkg/crowdsecconnection` — dest wrapping, not a CrowdSec fact. Leave it; do not clone.

**Process lifetime**

- DecisionStore is already a reclaim value on Traefik `New` ctx (`OpenDecisionStore` → `decisionstore.Open`). `countActive` belongs on that incarnation at create, not `sync.Once`, not a package global. Sister `pkg/reclaim` / `std_go_reclaim` / `core_plugin_middleware` already own the holder.

**Range**

- Dest still counts Range via `range:` slot keys with no store Peek. Requirement: omit Range from the store-owned gauge until debt. `ApplyRangeBatch` must not adjust the compact map. Do not query `RangeMembership.Remediation` / Helper `Contains`. Debt file already on this branch: `knowledge/debt/2026-09-20-range-active-decisions-forget.md` (IssueKey matches). `issues.md` already has the note-large row.

## Decisions

- Move the group-by onto DecisionStore; delete reporter `activeDecisionSlots` and `activeDecisionsByOriginIPType`.
- Count only stream/alone Ip and header-scope `PutMany` / `DeleteMany` (and memory `PublishTick` expiry of those slots). Live/none `Put` memo does not increment. Range is out of the gauge (omit, not peek).
- Reporter still POSTs `active_decisions` only when `crowdsecMode` is stream or alone; dropped window + processed atomics stay on the reporter; `OriginName` at POST; overflow origin id 0 stays empty name.
- Do not add a Go engine interface. Do not store `usageMetricKey` or LAPI item JSON in decisionstore. Do not add Redis intern table. Do not add `Store.Peek`.
- Spec fold: `core_plugin_lapi_usage-metrics` (drop per-slot forget map) and `core_plugin_decisionstore_store` (store owns the group-by). Do not silent-rename those packets (`core_plugin_decisionstore.md` vs spec `…_store` stays; not this ticket).

## Open questions

- Q: Who owns active-decision counts vs origin intern vs metrics POST shape?
  Decision: resolved — DecisionStore owns the compact `{originID, family} → int64` counts (updated inside PutMany/DeleteMany/memory PublishTick expiry). DecisionStore intern.Table already owns origin intern (`OriginID` / `OriginName`); reuse it, including in-process intern of a Redis MGET origin name. MetricsReporter / `pkg/lapi` owns POST shape (`usageMetricKey`, item JSON, `name=active_decisions` `unit=ip`, `OriginName` at emit). Reporter snapshots store counts; it does not keep a forget map. Do not copy intern or POST JSON into a third type.
  By: explore

- Q: Exact Store snapshot method name for POST?
  Decision: resolved — `ActiveCounts()` on `Store` returns a snapshot copy of `map[ActiveCountKey]int64` (`OriginID uint16`, `Family string`). Do not expose `usageMetricKey` or LAPI item structs from decisionstore.
  By: propose

- Q: Redis previous-origin parse — MGET bytes are KindOriginString; Unpack string → originID 0?
  Decision: resolved — MGET previous value, split `KindOriginString` for the origin name, then `Store.OriginID(name)` in-process. Do not persist intern ids on Redis. Do not add a Redis intern table. Family comes from `FamilyOfHostOrCIDR` on the slot identifier, not from Unpack.
  By: explore

- Q: Header-scope family — `FamilyOfHostOrCIDR` on the identifier, or a distinct family token?
  Decision: resolved — keep dest: `FamilyOfHostOrCIDR` on the decision value / slot identifier. Country/AS and other non-address identifiers POST empty `ip_type` (cscli still shows the origin row). Do not invent a `header` family token.
  By: explore

- Q: Does a shared DecisionStore let live Put increment a stream gauge?
  Decision: resolved — no extra isolation needed. SessionHex includes Mode, so stream/alone and live/none already Open different stores. `countActive` is set at create from that Open’s `crowdsecMode` (true only for stream/alone). Live Open keeps `countActive` false so memo `Put` cannot increment. Two live Clients sharing one store stay uncounted. Do not put `countActive` in `StoreKey`. Traefik `New` ctx remains the reclaim holder; no `sync.Once`.
  By: explore

- Q: Where does the compact map live (Store vs each engine)?
  Decision: resolved — one compact map on `Store`; memory and Redis hold a pointer (same pattern as memory `origins`). `ActiveCounts` is a Store method (no engine interface). Memory adjust runs under the same `mu` as `putSlot` / `deleteTickLocked` / PublishTick sweep (nested count mutex allowed). Redis adjust is in-process after MGET, under the Store count mutex (redis has no `mu` today). Overwrite of an existing canonical slot decrements the previous group then increments the new. Prior-spelling extra DEL is not a second gauge event (dest counted one `SlotKey`).
  By: propose

- Q: Redis TTL expiry — should counts drop when Redis keys expire without DeleteMany?
  Decision: assumed — no. Dest reporter also never sees Redis TTL. Redis `PublishTick` stays a no-op. Counts drop on DeleteMany / overwrite only. Out of scope: replacing tick maps, Redis intern table.
  By: explore

- Q: Range in the store-owned gauge?
  Decision: resolved — omit Range until debt is taken. Do not Peek membership. Do not adjust counts in `ApplyRangeBatch`. Remove dest `remember`/`forget` of `range:` keys in the same change (do not keep the reporter map only for Range). Debt: `knowledge/debt/2026-09-20-range-active-decisions-forget.md` (IssueKey `2026-09-20-store-active-decisions-gauge`); `issues.md` note-large already present.
  By: explore

- Q: Compact decision slot Language after the forget map is gone?
  Decision: resolved — updated `knowledge/devdocs/core_plugin_lapi_usage-metrics.md` and `knowledge/devdocs/core_plugin_decisionstore.md`; MetricsReporter no longer owns the gauge; compact group-by is DecisionStore. Stream-apply usage dropped remember/forget. Do not silent-rename the packet files. No extra Issues row (Range debt is the follow-up).
  By: implement
