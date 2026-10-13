# Requirement
IssueKey: 2026-09-30-intern-decision-scenario

## Why

Stream and live already receive `decision.Scenario`. Today `MetricsOrigin` keeps it only for `lists` (as `lists:<name>`), then the packed memory word drops it. We will need that raw name later for per-scenario usage metrics. Store it now without sending a `scenario` label yet.

## Decision

Keep every CrowdSec scenario (not only lists) on the in-memory decision, packed into the existing `uint32` word, so `LiveSlot` stays 8 bytes. Do not emit per-scenario metrics in this change.

**Two intern tables on `DecisionStore`.** Origins stay one table (folded `MetricsOrigin`, including `lists:<name>`). Scenarios get a second table for the raw LAPI `scenario`. Same rules as today: empty name is id `0`; overflow warns and stores `0`; append-only; not shared across reclaim keys. The metrics reporter does not own a table.

**Re-lay the packed word** (memory engine only). Origin is the small set; scenario is the large one. Kind no longer spends 8 bits on ASCII `t`/`c`/`f`:

```
  0  2            14 16              32
  ├k─┼── origin ──┼fa┼── scenario id ──┐
   2      12        2        16

  kind      0 empty / 1 t / 2 c / 3 f   (live still stores `f` for negative cache)
  origin    12 bits → 4095 folded origins
  family    unchanged (ActiveCounts walk still must not parse the slot key)
  scenario  16 bits → 65535 names
```

`unpack` can no longer be `uint16(word>>8)`. Origin overflow at pack is id `> 4095` (the intern table is `uint16`, but the word only packs 12 bits). Scenario overflow is the existing table max (65535).

**Overflow loses the name, not the decision.** Kind, family, and TTL stay. Id `0` is also the empty-name id, so “LAPI sent no scenario” and “table was full” look the same. Redis and the range blob stay `KindOriginString` / text; intern ids are process-local. Stream startup rebuilds memory from the full decision set.

**Lookup stays kind + origin.** `IncDropped`, `usageMetricKey`, and the “no scenario label” spec stay as they are until the series is posted. `active_decisions` can group by scenario later because it already walks the word. `dropped` only sees the id once lookup returns it.

Lists intern twice (`lists:firehol_level1` and `firehol_level1`) so today’s `origin` label does not change.

## Real-world sizes (distinct names, not decision rows)

| Bucket | Typical | Heavy | Packed cap |
|---|---|---|---|
| origin | 4–8 (`crowdsec`, `CAPI`, `cscli`, up to 3 console lists) | tens–low hundreds (enterprise list catalog) | 4095 |
| scenario | ~50–70 (linux+nginx + list names) | ~80–200; full hub ~780 | 65535 |

CAPI community-blocklist scenario names follow installed scenarios; they do not dump the whole hub.

## Out of scope

- Sending a `scenario` usage-metrics label or rewriting `origin` to `crowdsec:<scenario>` for `cscli`
- Widening Redis / range encoding
- Multi-decision-per-slot (`knowledge/debt/2026-09-19-multiple-decisions-per-cache-key.md`)
- A side field on `LiveSlot` (rejected: 12 bytes vs 8)

## Current pins this will change

- `openspec/specs/core_plugin_decisionstore_store/spec.md` — word is `uint32(kind[0]) | uint32(id)<<8 | familyCode<<24`
- `pkg/decisionstore/pack.go` — `packWord` / `unpackWord` / `packedOriginID`
- `pkg/lapi/client_decisions.go` — `streamPutItem` / live pick run `MetricsOrigin` and drop raw `Scenario`
- `pkg/intern/table.go` — one table type; origin pack must saturate at 12 bits

## Current (code)

- Packed word is `uint32(kind[0]) | uint32(originID)<<8 | familyCode<<24` (kind ASCII `t`/`c`/`f` in bits 0–7, intern origin in 8–23, family in 24–25). `unpackWord` / `packedOriginID` is `uint16(word>>8)`. `pkg/decisionstore/pack.go`
- Spec pins that same layout and one origin intern table. `openspec/specs/core_plugin_decisionstore_store/spec.md`
- `LiveSlot` is `Word uint32` plus `ExpiresAt int32` (8 bytes). No extra scenario field. `pkg/decisionstore/liveslot.go`
- `Store` holds one `origins *intern.Table`. `NewMemory` / `NewRedis` each `intern.New()`. Scenario intern table: not found. `pkg/decisionstore/store.go`
- `intern.Table` is append-only `uint16` (empty name is id 0; overflow returns `0, false` at 65535). No 12-bit saturate. `pkg/intern/table.go`
- Memory `pack` intern-overflow Warns `decisionstore:intern overflow` and packs origin id 0; family still packed. `pkg/decisionstore/memory.go`
- Store `Decision` has `Scope`, `Value`, `Kind`, `Origin`, `DurationSec`. No `Scenario`. `pkg/decisionstore/decision.go`
- LAPI JSON `Decision` already has `Scenario`. `pkg/lapi/client.go`
- Stream Ip/header `streamPutItem` sets `Origin` from `MetricsOrigin(item.Origin, item.Scenario)` and does not pass raw `Scenario` into the store. `pkg/lapi/client_decisions.go`
- Live pick does the same fold into `liveResult.origin`; `memoLive` Puts kind+origin only. `pkg/lapi/client_decisions.go` `pkg/lapi/client_live.go`
- Stream Range writes `KindOriginString(kind, MetricsOrigin(...))`. `pkg/lapi/client_stream.go`
- Redis Put is `KindOriginString`; intern ids stay in-process. `pkg/decisionstore/redis.go`
- `MetricsOrigin` keeps raw scenario only for `lists` (`lists:<name>`). Other origins drop it. `pkg/lapi/client_metrics.go`
- `IncDropped` / `usageMetricKey` take origin, ip_type, remediation. No scenario label. `pkg/lapi/client_metrics.go` `pkg/bouncer/bouncer.go`
- Usage-metrics spec: MUST NOT send a `scenario` item label; lists origin is `lists:` plus scenario. `openspec/specs/core_plugin_lapi_usage-metrics/spec.md`
- `LookupRemediation` returns kind, origin name, origin id. No scenario id. `pkg/decisionstore/store.go`
- `ActiveCounts` groups `OriginID` + family from the packed word; does not parse the slot key. `pkg/decisionstore/activecount.go`
- Live negative cache stores `f` (`NoBannedValue`). `pkg/decisionscope/lookup.go` `pkg/lapi/client_live.go`
- Multi-decision-per-slot is existing debt. `knowledge/debt/2026-09-19-multiple-decisions-per-cache-key.md`

## Out of scope

- Sending a `scenario` usage-metrics label, or rewriting `origin` to `crowdsec:<scenario>` for `cscli`.
- Changing `IncDropped`, `usageMetricKey`, or the “no scenario label” spec in this change.
- Widening Redis slots or the range blob past `KindOriginString`.
- A Redis or reporter intern table.
- Multi-decision-per-slot (`knowledge/debt/2026-09-19-multiple-decisions-per-cache-key.md`).
- A side field on `LiveSlot` (ticket rejected 12 bytes vs 8).

## Unknowns

- Whether raw scenario rides a new `Decision.Scenario` field or another Put argument; dest Decision has no scenario slot.
- Whether origin 12-bit saturate lives in `intern.Table.ID` or only in `packWord` (table type stays `uint16`).
- Warn text for origin overflow vs scenario overflow (dest has one `decisionstore:intern overflow` line).
- Whether `LookupRemediation` grows a scenario id now (ticket: lookup stays kind+origin; `dropped` sees the id once lookup returns it).
- Typical/heavy distinct-name sizes in the ticket table were not measured this prepare.
- CAPI community-blocklist scenario-name cardinality vs installed hub: vendor fact, not measured.

## Tensions

- Ticket: two intern tables on `DecisionStore`. Dest: one `origins` table. `pkg/decisionstore/store.go`
- Ticket: 2-bit kind enum (0 empty / 1 `t` / 2 `c` / 3 `f`). Dest: 8-bit ASCII `kind[0]`. `pkg/decisionstore/pack.go`
- Ticket: unpack must not be `uint16(word>>8)`. Dest `packedOriginID` is that. `pkg/decisionstore/pack.go`
- Ticket: origin overflow at id `> 4095`. Dest intern overflow is table max 65535. `pkg/intern/table.go` `pkg/decisionstore/memory.go`
- Ticket: intern raw LAPI `scenario` plus folded origin. Dest store Decision has no Scenario; stream/live drop it after `MetricsOrigin`. `pkg/decisionstore/decision.go` `pkg/lapi/client_decisions.go`
- Ticket: lists intern twice (`lists:firehol_level1` and `firehol_level1`). Dest stores only the folded origin string. `pkg/lapi/client_metrics.go`
- Ticket: `active_decisions` can group by scenario later because it already walks the word. Dest walk reads origin id + family only. `pkg/decisionstore/activecount.go`
