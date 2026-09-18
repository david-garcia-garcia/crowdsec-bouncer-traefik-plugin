# Requirement
IssueKey: 2026-09-18-typed-cache-origin-intern

## Problem
Stream/alone memory RSS at ~400K IP decisions stores each metrics origin as a string on every cache value (`kind` + U+001F + origin) and again on `activeDecisionSlots`. Closed PR 99 packed that in `pkg/cache` (`Stored`, `Packed`, `SetRemediation`, `\x1e` range-index). That codec is the wrong domain. Dest still has the string path and no intern table.

## Current (code)
- `cacheInterface` / `Client` expose string `Set`/`Get`/`GetMany`/`Delete` plus `Acquire`. No `SetInt`/`GetInt`. `pkg/cache/cache.go` `pkg/cache/acquire.go`
- Memory `localCache` type-asserts `ttl_map.Heap.Get` to `string` and stores strings via `Heap.Set`. Redis `set` writes `[]byte(value)`. No `MemoryBackend` type. `pkg/cache/cache.go` `vendor/github.com/leprosus/golang-ttl-map/map.go`
- `RemediationWithOrigin` / `RemediationKind` / `RemediationOrigin` live in `pkg/cache` (`\x1f` suffix). `pkg/cache/remediation.go`
- `SetRemediation`, `GetManyStored`, `Packed`, `Stored`, `Leftover`, `ParsePackedOriginID`: not found.
- `DecisionStore` is a reclaim value that owns only `*cache.Client`. No origin intern table. `pkg/lapi/decisionstore.go`
- Stream IP/header write: `MetricsOrigin` → `RemediationWithOrigin` → `cache.Set` + `rememberActiveDecision`. `pkg/lapi/client_decisions.go`
- Stream Range write: same string into `rangeUpserts`; `ApplyRangeBatch` `Set`s the `range-index` blob. `pkg/lapi/client_stream.go` `pkg/decisionscope/range.go`
- Range-index lines are `cidr=remediation` (letter or letter+`\x1f`+origin). `pkg/decisionscope/range.go` `pkg/decisionscope/scope.go`
- `LookupCachedRemediation` always `GetMany` strings and returns `RemediationKind` + `RemediationOrigin`. `pkg/decisionscope/lookup.go`
- Stream/alone request path uses that origin on drop; live/none splits origin from the leftover string. `pkg/bouncer/bouncer.go`
- `activeDecisionSlots` is `map[string]usageMetricKey` with a string `origin` and `ip.FamilyOfHostOrCIDR`. Forget needs the per-slot entry. `pkg/lapi/client_metrics.go`
- Origin intern / packed uint32 word / compact slot record: not found.
- Cache usage packet: DecisionStore owns a string bag; payloads are opaque strings; ban/captcha/none codes live on `pkg/decisionscope`. `knowledge/devdocs/core_cache_client.md`
- No packing public config field. `pkg/configuration/configuration.go`

## Desired
- `pkg/cache` stays a typed bag: keep string `Set`/`Get`/`GetMany`/`Delete`/`Acquire`. Add `SetInt`/`GetInt` (`uint32` is enough). Memory stores a machine word in `ttl_map`. Redis Int encoding (decimal string or 4 bytes) is opaque to callers. Cache MUST NOT know kind, origin, Packed, Stored, Remediation, or range-index separators. No `SetRemediation`. No `MemoryBackend` type switch for remediations.
- Origin intern table on `DecisionStore`: append-only name→`uint16`, lock-free `OriginName`. Pack word is store/lapi: `uint32(kind[0]) | uint32(id)<<8`. Overflow keeps leftover `RemediationWithOrigin` strings. Table is not a package var. Not shared across DecisionStore reclaim keys.
- `decisionscope` owns range-index line encoding (letter or letter+id as a string). That blob uses cache `Set`, never `SetInt`. Lookup/bouncer: `GetInt` for packed memory IPs; on miss or leftover, `Get` string. Resolve origin name from the store table only on drop. No second lock on the allow-path `GetInt`.
- Compact `activeDecisionSlots` to `originID` + family using the same store table. Keep the slot map (per-slot forget). Live/none and Redis may keep leftover strings.
- Do not extract stream/live/metrics into new packages. Intern stays off `Client` except thin forwards if tests need them. Update `knowledge/devdocs` cache usage: typed get/set; no remediation codec in `pkg/cache`.

## Affected
- `pkg/cache/cache.go` (`SetInt`/`GetInt`; memory word / Redis opaque Int)
- `pkg/cache/remediation.go` (must leave cache; leftover string path stays elsewhere)
- `pkg/lapi/decisionstore.go` (intern table)
- `pkg/lapi/client_decisions.go`, `pkg/lapi/client_stream.go` (pack on write; intern off Client except thin forwards)
- `pkg/decisionscope/lookup.go`, `pkg/decisionscope/range.go`, `pkg/bouncer/bouncer.go`
- `pkg/lapi/client_metrics.go` (compact slots)
- `knowledge/devdocs/core_cache_client.md` (and Redis usage if Int encoding is documented)
- Tests under `pkg/cache`, `pkg/lapi`, `pkg/decisionscope`, `pkg/bouncer`

## Out of scope
- Redis intern table
- Replacing `ttl_map`
- Dropping `activeDecisionSlots`
- New public config
- Full lapi package split / extracting stream, live, or metrics packages
- Reopening closed PR 99 / reusing branch `2026-09-18-pack-decision-origin`

## Unknowns
- Redis Int wire form (decimal vs 4 bytes) is caller-opaque; dest SimpleRedis has no Int helper (`vendor/github.com/david-garcia-garcia/traefik-middleware-utilities/simpleredis`).
- How `GetInt` miss vs leftover string is distinguished without a cache-owned Packed/Leftover type.
- Where leftover `RemediationWithOrigin` helpers live after they leave `pkg/cache`.
- Probe RSS at ~400K IPs is caller-stated; not reproduced this prepare.

## Tensions
- Ticket forbids cache knowing kind/origin; dest `RemediationKind`/`RemediationOrigin`/`RemediationWithOrigin` are in `pkg/cache`.
- Closed PR 99 put the codec in `pkg/cache`; dest never shipped that packed API (string suffix only).
- Ticket wants allow-path `GetInt` with no second lock; dest lookup is string `GetMany` plus Range membership.
- Ticket keeps intern off `Client`; dest stream write and metrics remember run on `Client`.
- Ticket says DecisionStore must stay in `lapi` this ticket (session hex would cycle if it leaves).
