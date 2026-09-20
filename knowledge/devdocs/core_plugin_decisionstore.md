# DecisionStore

## Language

**DecisionStore**:
A `pkg/decisionstore.Store` owned by one `lapi.Client` incarnation. Constructed in Client `create()` with `NewMemory` or `NewRedis`. Redis `keyPrefix` is CrowdSec cursor `SessionHex`. Two stream Clients that share a LAPI session share that child store. Live/none Clients that differ on Redis or `MetricsUpdateIntervalSeconds` each construct their own store.
_Avoid_: `pkg/cache`, `cache.Client`, `liveStore`, process `ttl_map`, `sync.Once`, utilities `reclaim`, sibling `OpenDecisionStore`

**Engine**:
Funcs bound at `NewMemory` or `NewRedis` (`memoryEngine` / `redisEngine`): BeginTick, PublishTick, Put, Delete, LookupRemediation, ApplyRangeBatch, RangeIndex, Close. A constructed Store always has those callbacks.
_Avoid_: a backend interface, `if mem` / `if red` on every method, nil-checking `s` or the funcs

**Origin intern**:
A `pkg/intern.Table` on one DecisionStore incarnation. Append-only `names` (`[]string`, index is id) plus `byName`. `ID` and `Name` are inverse. Id 0 is unused or overflow. Overflow does not wrap.
_Avoid_: package `var`, a table shared across store incarnations, leftover origin strings

**Packed word**:
A memory `uint32` of `kind[0]` in the low byte and intern id in the upper bits. Redis slots and the range-index blob stay `KindOriginString` (kind, optional newline, origin). Overflow Warns and packs origin id 0.
_Avoid_: leftover U+001F, packing inside a cache bag, intern ids in the range-index blob

**KindOriginString**:
The Redis SET value and the Range blob remediation: kind letter, then newline, then origin when origin is present. Letter-only is still a hit.
_Avoid_: leftover, `RemediationWithOrigin`, U+001F

## Overview

Construct a DecisionStore inside `lapi.Client` `create()` (`NewMemory` / `NewRedis`). Pass `SessionHex` as Redis `keyPrefix` for every mode. Do not Open the store on the Traefik `New` ctx as a sibling reclaim value. Client Close Closes the store. Sleep and Wake keep it. There is no second `liveStore`: live/none memo is Store Put and Lookup. `pkg/cache` must not exist as the DecisionStore bag. Stream lease (`updated` / `Acquire`) is gone; intra-instance skip is `core_plugin_lapi_stream-single-flight.md`.

## How to use

- Call `lapi.OpenStream` / `OpenLive`. Those create the Client; `create()` constructs the store. Do not call `decisionstore.Open` or `lapi.OpenDecisionStore`.
- Memory: in-process COW tick/published maps (`pubWord`/`pubExp`) plus the Range blob. Maps stay non-nil. Live Put mutates published maps in place and sweeps expired keys. Lookup holds `RLock` across probes.
- Redis: import `github.com/david-garcia-garcia/traefik-middleware-utilities/simpleredis` at `v1.0.5`. Prefix is `SessionHex` (cursor), not live `IdentityHex`. Logical keys are the client IP, header-scope key, and `range-index`. Writer plus optional readers; `nextReader` never retries the writer. SET/DEL are void. Do not re-patch `vendor/.../iplookup/helper.go` (`Helper.Contains` / `Count` RLock is upstream).
- Stream Redis disagreement shares the child store (first-wins Redis YAML). Live Redis disagreement isolates Clients and stores. Live metrics-interval split constructs two child stores (memory isolates; Redis still shares `SessionHex` keys).
- `decisionScopeHeaders` and poller intervals stay off Redis key composition. Stream `scopes=` and the store header-scope filter are the live-router union (`core_plugin_lapi_scope-union.md`).
- Stream apply calls Store `BeginTick` / `Put` / `Delete` / `PublishTick` / `ApplyRangeBatch` (`core_plugin_lapi_stream-apply.md`). Redis BeginTick/PublishTick are no-ops.
- Captcha grace is the gate cookie (`core_plugin_middleware_captcha-gate.md`), not store keys.
- Origin intern is a `pkg/intern.Table` field on `Store`. `OriginID` / `OriginName` forward to it. `Name` takes `RLock`. Resolve origin only on drop.
- `Store.Close()` drains Redis idle pools. Call it from `lapi.Client.Close`. Memory Close is a no-op. Safe to call more than once on a real Redis store. Do not Close a nil `*Store`. Sleep and Wake must not Close the store.

## Pattern snippet

```go
lapiClient, err := lapi.OpenStream(ctx, cfg, log, name, pluginVersion)
kind, origin, originID, err := lapiClient.LookupRemediation(remoteIP, ipAddr, scopes)
```

## Key files

- `pkg/decisionstore/store.go`
- `pkg/decisionstore/memory.go`
- `pkg/decisionstore/redis.go`
- `pkg/lapi/decisionstore.go`
- `pkg/intern/table.go`
- `pkg/lapi/session.go`
- `pkg/lapi/client.go`

## Gotchas

- Match miss and unreachable with `errors.Is(err, decisionstore.ErrMiss)` / `errors.Is(err, decisionstore.ErrUnreachable)`. Do not string-compare `err.Error()`.
- SessionHex stays. Existing Redis keys stay reachable. Changing the Client Open string does not migrate Redis keys.
- `lapi.Client.Sleep` / `Wake` must not Close the child store. `Close` must.
- On `create()` error after store New, Close the store before return.
- Stream store-write TTL is `int64(duration.Seconds())` with no clamp; a sub-second CrowdSec duration becomes `0`.
- Live and none writes use `liveCacheTTL` (substitute `defaultDecisionSeconds` when duration is empty). Stream must not use `liveCacheTTL`.
- After `Close()`, Redis Get/MGET/SET/DEL surface `store:unreachable` and must not open a new TCP connection.
- Do not copy `SimpleRedis` by value after `New`. Dial 2s and command 1s (not utilities zero-Config defaults).
- Yaegi-safe: do not put a map-holding type in an interface. `atomic.Value` holds only `*RangeMembership` and `string`.
- Callers MUST NOT import utilities `reclaim`.
