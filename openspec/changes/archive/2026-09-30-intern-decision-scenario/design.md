## Context

See `proposal.md` — Why. Dest memory word is `uint32(kind[0]) | originID<<8 | family<<24` with one origin intern table. Store `Decision` has no `Scenario`. Stream/live fold `MetricsOrigin` and drop the raw LAPI name. Explore locked two intern tables, the 2+12+2+16 word, saturate origin at `packWord`, and no usage-metrics `scenario` label.

Identity: `MetricsOrigin` owns the folded origin string. `FamilyOfHostOrCIDR` owns family at Put. Do not re-fold `lists:` in pack. Do not parse the slot key for family. Do not grow `LookupRemediation` with a second calculation of scenario.

## Goals / Non-Goals

**Goals:**

- Pack raw LAPI scenario into the existing 8-byte `LiveSlot` word.
- Keep lookup, dropped metrics, and `active_decisions` grouping on origin×family.
- Keep Redis / range as `KindOriginString`.

**Non-Goals:**

- A `scenario` usage-metrics label or `crowdsec:<scenario>` origin rewrite.
- Saturate inside `intern.Table.ID`.
- Redis intern ids or a reporter-owned table.
- Usage-doc Language/usage rewrite (implement / devdocs-impact updates `core_plugin_decisionstore.md`).

## Decisions

1. **`Decision.Scenario` field, not a Put argument** — Existing `Decision{}` literals stay valid (zero value is intern id 0). `streamPutItem` copies `item.Scenario`. `liveResult` grows a scenario string; `preferLiveResult` keeps the winner’s scenario the same way it keeps origin; `memoLive` Puts it. Alternative (extra Put argument) rejected: would reshape every `Put`/`PutMany` literal.

2. **Saturate origin in `packWord`, not `intern.Table.ID`** — Origin id `> 4095` packs as 0. Table type stays `uint16` max 65535 so the scenario table can share it. `memory.pack` Warns `decisionstore:intern overflow` on table overflow **or** packed-id saturate. Alternative (12-bit cap inside `ID`) rejected: would cap scenario names at 4095.

3. **Kind enum in bits 0–1; unpack returns ASCII** — Pack 0/1/2/3; `unpackWord` maps 1/2/3 to `t`/`c`/`f` so `lookupHits` / `PreferRemediation` keep string kinds. Live negative cache still stores `f`. Alternative (keep ASCII in 8 bits) rejected: ticket needs 16 bits for scenario.

4. **Bit extractors only on `ActiveCounts`** — `packedOriginID` is bits 2–13; `packedFamily` is bits 14–15; scenario is bits 16–31 (`packedScenarioID` for tests). Gauge key stays `{originID, family}`.

5. **Redis holds an unused second table** — `NewRedis` constructs Scenario intern for DecisionStore symmetry. Redis `PutMany` does not intern into the payload. Stream startup rebuilds memory from the full decision set.

6. **Distinct scenario overflow Warn** — Origin stays `decisionstore:intern overflow` (`TestMemoryInternOverflowWarns`). Scenario table overflow is `decisionstore:scenario intern overflow`. Do not change `intern.Table`. `FillUntilMaxForTest` stays origin-table fill. Tests that need 12-bit saturate intern past 4095 on origins; tests that need scenario overflow fill the scenario table to 65535.

## Risks / Trade-offs

- **[Risk] Dest packed-word tests pin `uint16(word>>8)` and low-byte ASCII `t`** → Mitigation: update `zzz_pack_test.go`, `zzz_memory_test.go`, lookup/activecount benches in the same change.
- **[Risk] Origin id 0 conflates empty name and overflow** → Mitigation: already dest semantics; ticket accepted it.
- **[Trade-off] Redis Put does not intern scenario** → Intern ids are process-local; memory rebuild on stream startup is the owner of packed ids.
- **[Trade-off] 12-bit origin cap is below table max** → Heavy origin catalogs (tens–low hundreds) fit 4095; overflow Warn is the safety net.

## Migration Plan

Single deploy. No Redis key format change. Memory maps rebuild from the next stream apply (`startup=true` after restart). Rollback is revert. No public config flag.

## Open Questions

None — explore rows stand; propose pinned the scenario overflow Warn string.
