# Explore

## Concepts

Store the raw LAPI scenario on the in-memory decision without emitting a `scenario` usage-metrics label. Origins stay one intern table (folded `MetricsOrigin`). Scenarios get a second table. Memory re-lays the existing `uint32` word; `LiveSlot` stays 8 bytes.

```
LAPI Decision.Scenario ──► MetricsOrigin(origin, scenario)
        │                         │
        │                         ▼
        │                   Origin intern (lists:name stays the origin label)
        │
        └── raw scenario ──► Scenario intern ──► pack into LiveSlot.Word (memory only)
                                                      │
                              Redis / range blob ─────┴── KindOriginString(kind, folded origin)
```

| Unit | Path | Job |
|------|------|-----|
| Packed word | `pkg/decisionstore/pack.go` | `packWord` / `unpackWord` / `packedOriginID` / `packedFamily` / `Unpack` / `KindOriginString` |
| Memory pack | `pkg/decisionstore/memory.go` `pack` / `putSlot` | Intern origin, Warn overflow, pack family from `FamilyOfHostOrCIDR` |
| LiveSlot | `pkg/decisionstore/liveslot.go` | `Word uint32` + `ExpiresAt int32` (8 bytes) |
| Store intern | `pkg/decisionstore/store.go` | One `origins *intern.Table`; `NewMemory` / `NewRedis` each `intern.New()` |
| intern.Table | `pkg/intern/table.go` | Append-only `uint16`; empty name id 0; overflow `0, false` at 65535 |
| Store Decision | `pkg/decisionstore/decision.go` | `Scope`, `Value`, `Kind`, `Origin`, `DurationSec` — no `Scenario` |
| LAPI Decision | `pkg/lapi/client.go` | JSON already has `Scenario` |
| Stream / live write | `pkg/lapi/client_decisions.go` | `streamPutItem` / live pick fold `MetricsOrigin` and drop raw scenario; `memoLive` Puts kind+origin only |
| Range / Redis text | `pkg/lapi/client_stream.go` `pkg/decisionstore/redis.go` | `KindOriginString`; intern ids process-local |
| Metrics origin | `pkg/lapi/client_metrics.go` | `lists` → `lists:<scenario>`; other origins drop scenario |
| Lookup | `pkg/decisionstore/lookup.go` `store.go` | Returns kind, origin name, origin id |
| ActiveCounts | `pkg/decisionstore/activecount.go` | Groups `packedOriginID` + `packedFamily`; does not parse the slot key |
| Dropped metrics | `pkg/bouncer/bouncer.go` `pkg/lapi/client_metrics.go` | `IncDropped` / `usageMetricKey` origin, ip_type, remediation — no scenario label |

Identity: this change does not set or reconstruct client address, user, tenant, Host, or trust hop. Family on the word stays `FamilyOfHostOrCIDR` at Put. Request IP stays `pkg/ip.GetRemoteIP`.

Call sites that matter (roots: worktree `pkg/**/*.go` for `packWord`, `unpackWord`, `packedOriginID`, `packedFamily`, `Unpack(`, `intern.New`, `.origins`, `LookupRemediation(`, `MetricsOrigin(`, `streamPutItem`, `memoLive`):

- Production `packWord`: **1** (`memory.pack`).
- Production `Unpack` of a packed word: **1** (`lookup.go` `hitFromPayload`).
- Production `packedOriginID` / `packedFamily` readers: **1** walk (`countPublishedSlots`) plus `unpackWord`.
- Production `intern.Table` construction: **2** (`NewMemory`, `NewRedis`). Production `ID` callers: **2** (`memory.pack`, `Store.OriginID`).
- Production `LookupRemediation` implementations / forwards: Store, memory engine, Redis engine, `lapi.Client`, **1** ServeHTTP caller (`pkg/bouncer/bouncer.go`).
- Production `MetricsOrigin` writers into the store: `streamPutItem`, live `queryLiveDecisions`, Range upsert in `client_stream.go`.
- Tests that pin the current word (`uint16(word>>8)`, ASCII `kind[0]`, single overflow Warn `decisionstore:intern overflow`): `pkg/decisionstore/zzz_pack_test.go`, `zzz_memory_test.go`, `zzz_activecount_bench_test.go`, `zzz_lookup_test.go`, `zzz_lookup_bench_test.go`.

Reproduce: **path run**. `go test ./pkg/intern ./pkg/decisionstore` passed (includes `TestPackUnpackMemoryWord`, `TestPackFamilyCodes`, `TestPackOverflowUsesGenericOrigin`, `TestMemoryInternOverflowWarns`, `TestIDOverflowDoesNotWrap`). `go test ./pkg/lapi -run "TestReportMetricsOmitsScenarioLabel|TestMetricsOrigin|TestIntern"` passed (`TestMetricsOriginListsRewrite`: `lists`+`firehol_level1` → `lists:firehol_level1`, `crowdsec`+`ssh-bf` → `crowdsec`; `TestReportMetricsOmitsScenarioLabel`: POST has no `scenario` label). Current layout matches dest: kind ASCII in bits 0–7, origin intern in 8–23, family in 24–25; `packedOriginID` is `uint16(word>>8)`; one origin table; store `Decision` has no scenario; overflow Warns `decisionstore:intern overflow` and packs origin id 0.

Outside facts: in-tree plus existing `knowledge/research/ext_crowdsec_lapi_usage-metrics/` (official bouncers fold `lists` into `origin=lists:<scenario>` and do not send a `scenario` label; `cscli metrics show bouncers` reads `origin` and `ip_type` only). Typical/heavy distinct-name sizes in the ticket table were not measured this explore. No new research slug.

Usage consume: `knowledge/devdocs/core_plugin_decisionstore.md` (Origin intern, Packed word, Active counts) and `core_plugin_lapi_usage-metrics.md` (no `scenario` item label). After apply those Packed-word / Origin-intern sections will be stale; do not rewrite them in explore. No `priority: always` packets. No Language write (Scenario intern does not exist on dest yet).

## Decisions

- Chosen seam: two intern tables on `DecisionStore` (origins stay folded `MetricsOrigin`; scenarios intern raw LAPI `scenario`). Re-lay the memory `uint32` to 2-bit kind enum + 12-bit origin + 2-bit family + 16-bit scenario id. `LiveSlot` stays `{uint32,int32}`.
- Carry raw scenario on a new `decisionstore.Decision.Scenario` field (zero value = empty id 0). `streamPutItem` copies LAPI `item.Scenario`; unexported `liveResult` grows a scenario string so `memoLive` can Put it. Origin on that struct stays `MetricsOrigin`.
- Saturate origin at pack (id `> 4095` → pack 0 + existing origin overflow Warn). `intern.Table.ID` stays `uint16` max 65535 so the scenario table can share the type.
- `unpackWord` maps kind 1/2/3 back to `t`/`c`/`f` so `lookupHits` / `PreferRemediation` keep string kinds. Redis and the range blob stay `KindOriginString` letters + folded origin.
- Lookup, `IncDropped`, `usageMetricKey`, and the “no scenario label” spec stay as they are. `ActiveCounts` still groups origin id + family; `packedOriginID` / `packedFamily` must follow the new bit layout so today’s gauge still works.
- Lists intern twice: origin table `lists:firehol_level1`, scenario table `firehol_level1`.
- Overflow loses the name, not the decision. Id 0 remains empty-name and overflow. Intern ids stay process-local.

Rejected alternatives:

- Side field on `LiveSlot` (12 bytes vs 8) — Out of scope; ticket rejected it.
- 12-bit saturate inside `intern.Table.ID` — would cap the scenario table at 4095; pins say table type stays `uint16`.
- Reporter-owned intern table — ticket forbids it.
- Emit a `scenario` usage-metrics label, or rewrite `origin` to `crowdsec:<scenario>` for `cscli` — Out of scope.
- Widen Redis / range encoding past `KindOriginString` — Out of scope.
- Grow `LookupRemediation` with a scenario id this change — ticket: lookup stays kind + origin.
- Extra Put argument instead of `Decision.Scenario` — would reshape `Put`/`PutMany` for every literal; a new field keeps existing callers working.

Live contract: `openspec/specs/core_plugin_decisionstore_store/spec.md` (word `uint32(kind[0]) | originID<<8 | family<<24`, one origin intern table, `LookupRemediation` kind+origin+id, ActiveCounts origin×family) and `openspec/specs/core_plugin_lapi_usage-metrics/spec.md` (MUST NOT send a `scenario` item label; lists origin is `lists:` plus scenario). Propose deltas those leaves. No new intern-table spec leaf.

## Open questions

- Q: Does raw scenario ride a new `Decision.Scenario` field or another Put argument?
  Rank: additive incidental — new field on `decisionstore.Decision`; existing `Decision{}` literals keep working (zero value is empty id 0); Unknowns lists the surface, no criterion names field vs extra argument
  Decision: assumed — add `Scenario` on `decisionstore.Decision`. `streamPutItem` copies LAPI `item.Scenario`. Grow unexported `liveResult` with a scenario string so `memoLive` Puts it. Do not add a parallel Put argument.
  By: explore

- Q: Does origin 12-bit saturate live in `intern.Table.ID` or only in `packWord`?
  Rank: additive asked — Current pins: origin pack must saturate at 12 bits; table type stays `uint16`
  Decision: resolved — saturate in `packWord` (origin id `> 4095` packs as 0). `intern.Table.ID` stays overflow at 65535 so the scenario table can use the same type.
  By: explore

- Q: What Warn text for origin overflow vs scenario overflow?
  Rank: additive incidental — dest has one `decisionstore:intern overflow` line; no criterion names the strings
  Decision: assumed — origin overflow (table max or pack saturate `> 4095`) stays `decisionstore:intern overflow`. Scenario table overflow is `decisionstore:scenario intern overflow`. Do not change `intern.Table`.
  By: propose

- Q: Does `LookupRemediation` grow a scenario id now?
  Rank: additive asked — Decision: lookup stays kind + origin; Out of scope: changing `IncDropped`, `usageMetricKey`, or the no-scenario-label spec
  Decision: resolved — do not grow `LookupRemediation`, `lookupHit`, or `engine.lookup` this change. Packed scenario id stays in the word for a later series. Production callers enumerated: Store, memory, Redis, `lapi.Client`, one ServeHTTP site in `pkg/bouncer/bouncer.go`.
  By: explore

- Q: Are the ticket typical/heavy distinct-name sizes accurate enough to pack origin in 12 bits and scenario in 16?
  Rank: additive asked — Decision table is the commissioned bound; Unknowns: not measured this prepare
  Decision: assumed — use the ticket table. Heavy origins (tens–low hundreds) fit in 4095; heavy scenarios (~80–200, full hub ~780) fit in 65535. Overflow already defined. Do not block on measuring.
  By: explore

- Q: Do CAPI community-blocklist scenario names dump the whole hub or follow installed scenarios?
  Rank: additive asked — Unknowns: vendor fact, not measured; Decision: they follow installed scenarios
  Decision: assumed — follow the ticket: names follow installed scenarios, not the whole hub. Overflow is the safety net. Existing `ext_crowdsec_lapi_usage-metrics` already records that official bouncers do not send a `scenario` label.
  By: explore

- Q: Do Redis Puts intern scenario even though Redis cannot roundtrip intern ids?
  Rank: additive asked — Decision: two intern tables on DecisionStore; Out of scope: widening Redis / range encoding
  Decision: assumed — `NewMemory` and `NewRedis` both hold a second `intern.Table`. Redis Put stays `KindOriginString(kind, folded origin)` with no intern id in the payload. Memory `pack` is the intern+pack site. `Unpack` of a string already returns origin id 0. Stream startup rebuilds memory from the full decision set.
  By: explore

- Q: Do Range upserts intern scenario despite the blob staying `KindOriginString`?
  Rank: additive asked — Out of scope: widening the range blob past `KindOriginString`
  Decision: resolved — Range upserts stay `KindOriginString(kind, MetricsOrigin)`. No packed intern id in the blob.
  By: explore

- Q: Does unpack of the 2-bit kind enum still return ASCII `t` / `c` / `f`?
  Rank: bounded asked — Decision re-lays kind to 0 empty / 1 `t` / 2 `c` / 3 `f`; enumerated 1 production `Unpack` consumer (`lookup.go` `hitFromPayload`) plus pack/lookup tests under `pkg/decisionstore`
  Decision: assumed — pack the enum; `unpackWord` still returns `BannedValue` / `CaptchaValue` / `NoBannedValue` so `lookupHits` and `PreferRemediation` keep string kinds. Live negative cache still stores `f`.
  By: explore

- Q: Does `ActiveCounts` group by scenario this change?
  Rank: additive asked — Decision: `active_decisions` can group later; Out of scope: sending a scenario usage-metrics label
  Decision: resolved — `ActiveCounts` stays `{originID, family}`. Update `packedOriginID` / `packedFamily` for the new bit layout so today’s gauge still works. Do not add scenario to the gauge key.
  By: explore

- Q: What language term for the second intern table?
  Rank: additive asked — Decision: two intern tables; dest packet already names Origin intern
  Decision: resolved — Scenario intern, parallel to Origin intern in `core_plugin_decisionstore.md`.
  By: devdocsimpact
