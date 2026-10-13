## 1. Packed word

- [x] 1.1 Re-lay `packWord` to 2-bit kind enum (0 empty / 1 `t` / 2 `c` / 3 `f`) + 12-bit origin + 2-bit family + 16-bit scenario id in `pkg/decisionstore/pack.go`
- [x] 1.2 Saturate origin id `> 4095` to 0 inside `packWord`; keep `intern.Table.ID` at uint16 max 65535
- [x] 1.3 Map `unpackWord` kind 1/2/3 back to ASCII `t`/`c`/`f`; update `packedOriginID` / `packedFamily`; add `packedScenarioID`

## 2. Store intern tables

- [x] 2.1 Add `Decision.Scenario`; construct a second `intern.Table` in `NewMemory` and `NewRedis`
- [x] 2.2 `newMemory` and `newRedis` each construct origin and scenario intern tables; `memory.pack` calls `ID`; pack origin id 0 with no log on table overflow or 12-bit saturate; pack scenario id 0 with no log on scenario table overflow; keep kind, family, origin (when not origin-overflow), and TTL
- [x] 2.3 Add `ScenarioName` (and scenario-table fill for tests) as the origin-table sibling; do not grow `LookupRemediation`

## 3. Stream and live write

- [x] 3.1 Copy LAPI `item.Scenario` in `streamPutItem`; keep `Origin` as `MetricsOrigin`
- [x] 3.2 Carry raw scenario on `liveResult`; `preferLiveResult` keeps the winner’s scenario; `memoLive` Puts it
- [x] 3.3 Leave Redis `PutMany` and Range upserts on `KindOriginString(kind, folded origin)`

## 4. Tests

- [x] 4.1 Update `zzz_pack_test.go` for the new layout (no `uint16(word>>8)`, unpack returns `t`/`c`/`f`)
- [x] 4.2 Add origin 12-bit saturate, lists intern twice (`lists:firehol_level1` + `firehol_level1`), and silent overflow pack-zero tests (`TestMemoryInternOverflowPacksZero`)
- [x] 4.3 Keep `TestReportMetricsOmitsScenarioLabel` and `TestMetricsOriginListsRewrite`; assert `ActiveCounts` still groups origin×family when a scenario is packed
- [x] 4.4 Run `go test ./pkg/intern ./pkg/decisionstore ./pkg/lapi ./pkg/bouncer`
