# DecisionStore

## Language

**DecisionStore**:
A reclaim value (`pkg/decisionstore.Store`) that owns one memory or Redis engine. Isolation is by store key: CrowdSec cursor `SessionHex` only. Two `lapi.Client` incarnations that share that key share remediations. `streamReady` and `streamPollInFlight` on the store own the CrowdSec cursor and the applied cache, not this HTTP client.
_Avoid_: `pkg/cache`, `cache.Client`, `liveStore`, process `ttl_map`, `sync.Once`, utilities `reclaim`

**CreatedBy**:
The Traefik `New(..., name)` string written once on the create that first put this store. Exclusive ownership of the SessionHex store is this string, not the Client Open key.
_Avoid_: router name, Host, bouncer API key in the reclaim key, a second middleware-name registry

**Engine**:
Funcs bound at `NewMemory` or `NewRedis` (`memoryEngine` / `redisEngine`): BeginTick, PublishTick, PutMany, DeleteMany, PeekMany, LookupRemediation, ApplyRangeBatch, RangeIndex, Close. Put and Delete are one-item wrappers. PeekMany is “what was there?” for the gauge; engines do not increment or decrement. A constructed Store always has those callbacks.
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

**Active counts**:
The compact `{originID, family} → int64` group-by of stream/alone Ip and header-scope slots on one DecisionStore. `countActive` is set at Open/New from crowdsecMode (true only for stream/alone), is not part of the reclaim StoreKey, and is not a field on the engine. PutMany/DeleteMany Peek then adjust in one Store path. `ActiveCounts` is a snapshot copy for usage-metrics POST.
_Avoid_: a reporter forget map, `usageMetricKey` in decisionstore, counting Range or live/none Put

**Elapsed slot clock**:
Process-wide `time.Time` at package load. Memory `LiveSlot.ExpiresAt` and `PublishTick(now int32)` use whole seconds from `time.Since` that origin plus two (`ElapsedNow()`), not wall Unix. `PublishTick(0)` skips the expiry sweep.
_Avoid_: `time.Now().Unix()` as PublishTick `now` on memory, treating `ExpiresAt` as wall Unix, homemade CAS on Unix elapsed

## Overview

Open a DecisionStore with `lapi.OpenDecisionStore` on the same Traefik `New` ctx as `OpenStream` / `OpenLive`. Pass `SessionHex` as Redis `keyPrefix` for every mode. Do not restore a package-level map. Do not Close the store from `lapi.Client.Close`. There is no second `liveStore`: live/none memo is Store Put and Lookup. `pkg/cache` must not exist as the DecisionStore bag. Stream lease (`updated` / `Acquire`) is gone; intra-instance skip is `core_plugin_lapi_stream-single-flight.md`.

## How to use

- Call `lapi.OpenDecisionStore(ctx, cfg, log, name)` then `lapi.New(..., store)` (or `OpenStream` / `OpenLive`, which Peek then Open the store first). `name` is Traefik `New(..., name)`. `OpenDecisionStore` sets `countActive` true only for stream/alone. Do not hash `countActive` into StoreKey.
- Memory: in-process COW tick/published `map[string]LiveSlot` plus the Range blob. Maps stay non-nil. Each `LiveSlot.ExpiresAt` is int32 elapsed seconds on the package clock (eight-byte `{uint32,int32}` slots). Live PutMany copy-on-writes onto published (one clone, then sweep expired keys with `elapsedNow()`). Published slots are `atomic.Value` of `*publishedSlots`; lookup `Load`s and does not take `mu`. Expiry compare uses the same elapsed clock.
- Redis: import `github.com/david-garcia-garcia/traefik-middleware-utilities/simpleredis` at `v1.0.6`. Prefix is `SessionHex` (cursor), not live `IdentityHex`. Logical keys are the client IP, header-scope key, and `range-index`. Writer plus optional readers; `nextReader` never retries the writer. MSetEX/DEL are void. Do not re-patch `vendor/.../iplookup` (Contains RLock and IPv4 four-byte walk are upstream).
- Same store key → same Store. Redis YAML change reuses the existing engine (first-wins). Exclusive ownership is write-once `createdBy`, not a Redis hash.
- `streamReady` / `streamPollInFlight` stay on the store across Client reincarnation. Do not zero them in `lapi.New`. Stream skip is `TryBeginStreamPoll` (`core_plugin_lapi_stream-single-flight.md`).
- `decisionScopeHeaders` and poller intervals stay off the store key. Stream `scopes=` and the store header-scope filter are the live-router union (`core_plugin_lapi_scope-union.md`).
- Stream apply calls Store `BeginTick` / `DeleteMany` / `PutMany` / `PublishTick(ElapsedNow())` / `ApplyRangeBatch` (`core_plugin_lapi_stream-apply.md`). Memory `PublishTick(0)` skips expiry sweep; non-zero `now` drops tick slots where `ExpiresAt > 0 && ExpiresAt <= now` and does not decrement the gauge. Redis tick methods are no-ops and ignore `now`; Redis PutMany is MSetEX by TTL in `PutManyChunk` batches. When `countActive`, Store PeekMany (memory tick/published, Redis MGET) then adjusts before the engine write.
- Snapshot origin×family counts with `Store.ActiveCounts` at usage-metrics POST. Do not store `usageMetricKey` or LAPI item JSON in decisionstore. `ApplyRangeBatch` does not adjust the gauge. Memory PublishTick expiry and Redis TTL without DeleteMany do not decrement.
- Captcha grace is the gate cookie (`core_plugin_middleware_captcha-gate.md`), not store keys.
- Origin intern is a `pkg/intern.Table` field on `Store`. `OriginID` / `OriginName` forward to it. `Name` takes `RLock`. Resolve origin only on drop.
- `Store.Close()` logs `crowdsec decision store closed` then drains Redis idle pools. Memory Close is a no-op drain. Call Close only from the store’s reclaim Close hook. Safe to call more than once on a real Redis store. Do not Close a nil `*Store`.
- Install log-only Sleep/Wake (`crowdsec decision store sleeping` / `waking`). They MUST NOT drain Redis or drop maps. Create logs `crowdsec decision store started`. `reclaim_put|orphan|reclaim|dispose` stay DEBUG.

## Pattern snippet

```go
store, err := lapi.OpenDecisionStore(ctx, cfg, log, name)
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
- SessionHex stays the Redis `keyPrefix`. StoreKey does not hash Redis params. Existing Redis keys stay reachable. Changing the Client Open string does not migrate Redis keys.
- `lapi.Client.Close` / `Sleep` must not Close the shared store. Sleep and Wake keep the DecisionStore warm.
- Stream store-write TTL is `int64(duration.Seconds())` with no clamp; a sub-second CrowdSec duration becomes `0`.
- Live and none writes use `liveCacheTTL` (substitute `defaultDecisionSeconds` when duration is empty). Stream must not use `liveCacheTTL`.
- After `Close()`, Redis Get/MGET/SET/DEL/MSetEX surface `store:unreachable` and must not open a new TCP connection.
- Do not copy `SimpleRedis` by value after `New`. Dial 2s and command 1s (not utilities zero-Config defaults).
- Memory expiry is elapsed-only: wall Unix in `PublishTick` or lookup would treat every slot as expired after stream apply.
- Yaegi-safe: do not put a map-holding type in an interface. Store `atomic.Value` holds `*RangeMembership` and `string`. Memory published snapshot is `*publishedSlots`, not the map.
- `ActiveCounts` does not drop on memory PublishTick expiry or Redis TTL. A later DeleteMany of a missing key is a no-op, so the gauge can stay high until overwrite or an explicit delete of a still-present slot.
