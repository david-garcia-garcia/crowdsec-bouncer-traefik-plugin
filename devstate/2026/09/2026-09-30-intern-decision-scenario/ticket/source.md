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
