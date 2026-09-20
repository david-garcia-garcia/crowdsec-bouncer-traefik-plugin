# DecisionStore

## Language

**DecisionStore**:
A reclaim value (`pkg/decisionstore.Store`) that owns one memory or Redis engine. Isolation is by store key: CrowdSec cursor `SessionHex` plus Redis store parameters. Two `lapi.Client` incarnations that share that key share remediations.
_Avoid_: `pkg/cache`, `cache.Client`, `liveStore`, process `ttl_map`, `sync.Once`, utilities `reclaim`

**Engine**:
Funcs bound at `NewMemory` or `NewRedis` (`memoryEngine` / `redisEngine`): BeginTick, PublishTick, PutMany, DeleteMany, LookupRemediation, ApplyRangeBatch, RangeIndex, Close. Put and Delete are one-item wrappers. A constructed Store always has those callbacks.
_Avoid_: a backend interface, `if mem` / `if red` on every method, nil-checking `s` or the funcs

**Origin intern**:
A `pkg/intern.Table` on one DecisionStore incarnation. Append-only `names` (`[]string`, index is id) plus `byName`. `ID` and `Name` are inverse. Id 0 is unused or overflow. Overflow does not wrap.
_Avoid_: package `var`, a table shared across store reclaim keys, leftover origin strings

**Packed word**:
A memory `uint32` of `kind[0]` in the low byte and intern id in the upper bits. Redis slots and the range-index blob stay `KindOriginString` (kind, optional newline, origin). Overflow Warns and packs origin id 0.
_Avoid_: leftover U+001F, packing inside a cache bag, intern ids in the range-index blob

**KindOriginString**:
The Redis SET value and the Range blob remediation: kind letter, then newline, then origin when origin is present. Letter-only is still a hit.
_Avoid_: leftover, `RemediationWithOrigin`, U+001F

**Elapsed slot clock**:
Process-wide `time.Time` at package load. Memory `LiveSlot.ExpiresAt` and `PublishTick(now int32)` use whole seconds from `time.Since` that origin plus two (`ElapsedNow()`), not wall Unix. `PublishTick(0)` skips the expiry sweep.
_Avoid_: `time.Now().Unix()` as PublishTick `now` on memory, treating `ExpiresAt` as wall Unix, homemade CAS on Unix elapsed

## Overview

Open a DecisionStore with `lapi.OpenDecisionStore` on the same Traefik `New` ctx as `OpenStream` / `OpenLive`. Pass `SessionHex` as Redis `keyPrefix` for every mode. Do not restore a package-level map. Do not Close the store from `lapi.Client.Close`. There is no second `liveStore`: live/none memo is Store Put and Lookup. `pkg/cache` must not exist as the DecisionStore bag. Stream lease (`updated` / `Acquire`) is gone; intra-instance skip is `core_plugin_lapi_stream-single-flight.md`.

## How to use

- Call `lapi.OpenDecisionStore(ctx, cfg, log)` then `lapi.New(..., store)` (or `OpenStream` / `OpenLive`, which Open the store first).
- Memory: in-process COW tick/published `map[string]LiveSlot` plus the Range blob. Maps stay non-nil. Each `LiveSlot.ExpiresAt` is int32 elapsed seconds on the package clock (eight-byte `{uint32,int32}` slots). Live PutMany copy-on-writes onto published (one clone, then sweep expired keys with `elapsedNow()`). Lookup holds `RLock` across probes and compares expiry on the same clock.
- Redis: import `github.com/david-garcia-garcia/traefik-middleware-utilities/simpleredis` at `v1.0.5`. Prefix is `SessionHex` (cursor), not live `IdentityHex`. Logical keys are the client IP, header-scope key, and `range-index`. Writer plus optional readers; `nextReader` never retries the writer. MSetEX/DEL are void. Do not re-patch `vendor/.../iplookup/helper.go` (`Helper.Contains` / `Count` RLock is upstream).
- Same store key → same Store. Different Redis hosts (or enabled/password/database/read hosts) isolate.
- `decisionScopeHeaders` and poller intervals stay off the store key. Stream `scopes=` and the store header-scope filter are the live-router union (`core_plugin_lapi_scope-union.md`).
- Stream apply calls Store `BeginTick` / `DeleteMany` / `PutMany` / `PublishTick(ElapsedNow())` / `ApplyRangeBatch` (`core_plugin_lapi_stream-apply.md`). Memory `PublishTick(0)` skips expiry sweep; non-zero `now` drops tick slots where `ExpiresAt > 0 && ExpiresAt <= now`. Redis tick methods are no-ops and ignore `now`; Redis PutMany is MSetEX by TTL in `PutManyChunk` batches.
- Captcha grace is the gate cookie (`core_plugin_middleware_captcha-gate.md`), not store keys.
- Origin intern is a `pkg/intern.Table` field on `Store`. `OriginID` / `OriginName` forward to it. `Name` takes `RLock`. Resolve origin only on drop.
- `Store.Close()` drains Redis idle pools. Call it only from the store’s reclaim Close hook. Memory Close is a no-op. Safe to call more than once on a real Redis store. Do not Close a nil `*Store`.

## Pattern snippet

```go
store, err := lapi.OpenDecisionStore(ctx, cfg, log)
lapiClient, err := lapi.New(cfg, log, pluginVersion, store)
kind, origin, originID, err := lapiClient.LookupRemediation(remoteIP, ipAddr, scopes)
```

## Key files

- `pkg/decisionstore/store.go`
- `pkg/decisionstore/memory.go`
- `pkg/decisionstore/redis.go`
- `pkg/lapi/decisionstore.go`
- `pkg/intern/table.go`
- `pkg/lapi/session.go`

## Gotchas

- Match miss and unreachable with `errors.Is(err, decisionstore.ErrMiss)` / `errors.Is(err, decisionstore.ErrUnreachable)`. Do not string-compare `err.Error()`.
- SessionHex and store Redis params stay. Existing Redis keys stay reachable. Changing the Client Open string does not migrate Redis keys.
- `lapi.Client.Close` / `Sleep` must not Close the shared store. Sleep and Wake keep the DecisionStore warm.
- Stream store-write TTL is `int64(duration.Seconds())` with no clamp; a sub-second CrowdSec duration becomes `0`.
- Live and none writes use `liveCacheTTL` (substitute `defaultDecisionSeconds` when duration is empty). Stream must not use `liveCacheTTL`.
- After `Close()`, Redis Get/MGET/SET/DEL/MSetEX surface `store:unreachable` and must not open a new TCP connection.
- Do not copy `SimpleRedis` by value after `New`. Dial 2s and command 1s (not utilities zero-Config defaults).
- Memory expiry is elapsed-only: wall Unix in `PublishTick` or lookup would treat every slot as expired after stream apply.
- Yaegi-safe: do not put a map-holding type in an interface. `atomic.Value` holds only `*RangeMembership` and `string`.
