## Purpose

The reclaim value that holds CrowdSec Ip, header, and Range decisions on a memory or Redis engine.

## Requirements

### Requirement: DecisionStore is a reclaim value that owns the engine
A DecisionStore SHALL be `pkg/decisionstore.Store`, opened with `reclaim.OpenWithHooks` on the process table using the same Traefik `New` context as `lapi.Open`. Callers SHALL Peek that store key before Open (`core_plugin_lapi_reclaim-key`). `lapi.OpenDecisionStore` SHALL take the Traefik name so create() can write `createdBy`. The store SHALL bind engine funcs at `NewMemory` or `NewRedis` (`memoryEngine` / `redisEngine`): BeginTick, PublishTick, PutMany, DeleteMany, ActiveCounts, LookupRemediation, ApplyRangeBatch, RangeIndex, Close. Put and Delete SHALL be one-item wrappers around PutMany and DeleteMany. A constructed Store SHALL always have those callbacks. Store methods MUST NOT nil-check `s` or the engine funcs. Close SHALL be safe to call more than once on a real Redis store; tests MUST NOT Close a nil `*Store`. Dispatch MUST NOT be a backend interface and MUST NOT branch `if mem` / `if red` on every method. Yaegi-safe: the engine MUST NOT put a map-holding type in an interface; `map[string]LiveSlot` SHALL always be non-nil; intern SHALL be `[]string` plus `map[string]uint16`; Store `atomic.Value` SHALL hold only `*RangeMembership` and `string`. Memory published slots SHALL be `atomic.Value` of `*publishedSlots` (not the map). Memory `LookupRemediation` MUST NOT take `mu`; writers still `Lock` to clone and Store. The store SHALL install Sleep and Wake hooks that only log; they MUST NOT drain Redis or drop maps. The package MUST NOT keep a process-wide map or a `sync.Once`. Callers MUST NOT import utilities `reclaim`. There SHALL NOT be a second `liveStore` type: live/none memo is Store Put and Lookup. `pkg/cache` MUST NOT exist as the DecisionStore bag. Client address, when this leaf mentions it, SHALL reuse `pkg/ip.GetRemoteIP`. CrowdSec cursor identity SHALL reuse `SessionHex` / `streamSession`.

#### Scenario: Interval mismatch still shares one store
- **WHEN** two live `New` calls use the same Traefik name, the same LAPI URL and key, and the same Redis store parameters and differ only on `lapiUpdateIntervalSeconds`
- **THEN** both expose the same Store incarnation
- **AND** a ban written by the first is a hit for the second

#### Scenario: Last store holder Close drains Redis
- **WHEN** the last constructor context bound to a DecisionStore key is cancelled and grace elapses
- **THEN** Redis `Close` runs once
- **AND** a later Lookup on that closed Redis store is unreachable

#### Scenario: Redis Close twice is safe
- **WHEN** a constructed Redis Store Close runs twice
- **THEN** the second Close does not panic
- **AND** later Lookup is unreachable

#### Scenario: Store create sleeps wakes and closes at INFO
- **WHEN** a DecisionStore is created, last-holder Sleeps, Open during grace Wakes, then Close runs
- **THEN** INFO lines include `crowdsec decision store started`, `sleeping`, `waking`, and `closed`
- **AND** each line carries `storeKey`, `engine`, and `reason`
- **AND** `reclaim_put` is absent at INFO

### Requirement: Store key is SessionHex only
The DecisionStore reclaim key SHALL be `decisionstore:` plus `SessionHex`. Which knobs enter `SessionHex` is owned by `core_plugin_lapi_reclaim-key` (JSON field names on that marshaler change in this change and produce a new hash; a process restart builds a new store prefix). That key MUST NOT include `lapiUpdateIntervalSeconds`, `lapiMetricsUpdateIntervalSeconds`, `lapiUpdateMaxFailure`, `bouncerDecisionScopeHeaders`, TLS, failure action, `bouncerStartupBlock`, live-cache TTL, or middleware name. Stream `scopes=` and the store header-scope filter are owned by `core_plugin_lapi_scope-union`. Existing Redis keys under the previous hash are not migrated.

#### Scenario: Different Redis hosts share one store
- **WHEN** two stream Clients share Traefik name, LAPI URL and key and use different `lapiRedisHost` while Redis is off
- **THEN** one DecisionStore incarnation exists
- **AND** a ban written by the first is a hit for the second

#### Scenario: Header-map mismatch still shares remediations
- **WHEN** two stream Clients share Traefik name, LAPI URL, and key and differ only on `bouncerDecisionScopeHeaders`
- **THEN** they Open the same DecisionStore
- **AND** an IP ban written by the first is a hit for the second

### Requirement: Store createdBy is write-once Traefik name
A DecisionStore SHALL hold `createdBy` as the Traefik `New(..., name)` string from the create() that first put the store. Later Open/Wake MUST NOT overwrite it. Peek callers SHALL compare that string to the current constructor name (`core_plugin_lapi_reclaim-key`). An empty string is a valid owner.

#### Scenario: create writes createdBy once
- **WHEN** OpenDecisionStore create() runs for Traefik name `foo`
- **AND** a later Open with the same name Wakes that store
- **THEN** `createdBy` is still `foo`

### Requirement: Store streamReady is set after the first finished stream poll
A DecisionStore SHALL hold `streamReady` as an `int64` field published with `atomic.LoadInt64` / `StoreInt64` (not `atomic.Bool` or `atomic.Int64` as a struct field). The first stream poll that finishes successfully SHALL set it. A new `lapi.Client` SHALL read it before the first GET (`core_plugin_lapi_stream-single-flight`). Live/none MUST NOT require this flag for exclusive-name or store preserve.

#### Scenario: Finished stream poll marks the store ready
- **WHEN** `handleStreamCache` completes a successful stream fetch on a store
- **THEN** a later load of that store’s `streamReady` is non-zero

### Requirement: Store streamPollInFlight is the session skip
A DecisionStore SHALL hold `streamPollInFlight` as an `int64` field published with `CompareAndSwapInt64` / `StoreInt64`. Comments on `streamReady` and `streamPollInFlight` SHALL say they own the CrowdSec cursor and the applied cache, not this HTTP client. `Open`, Wake, and `lapi.New` MUST NOT store 0 onto those fields. `handleStreamTicker` SHALL enter with `TryBeginStreamPoll` (`core_plugin_lapi_stream-single-flight`).

#### Scenario: Second enter skips while the store poll is held
- **WHEN** `TryBeginStreamPoll` has already succeeded on a store
- **AND** a later `handleStreamTicker` runs against that store
- **THEN** the later enter is skipped

### Requirement: Redis prefix is SessionHex for every mode
When Redis is enabled, every GET/MGET/SET/DEL key the store sends SHALL be prefixed with `SessionHex` of that cursor. Live/none MUST NOT use `IdentityHex` as the prefix. Memory backends SHALL ignore the prefix string and isolate by owning the store’s maps. Two stores that share a Redis host and different prefixes MUST NOT observe each other’s decisions.

#### Scenario: Same Redis host two store prefixes
- **WHEN** two DecisionStores share one Redis-protocol host and different `SessionHex` prefixes
- **AND** the first Puts a banned IP
- **THEN** the second’s Lookup of that IP is a miss

#### Scenario: Live prefix is SessionHex not IdentityHex
- **WHEN** a live Client Opens a DecisionStore
- **THEN** Redis keys use `SessionHex` as the prefix
- **AND** that prefix is not `IdentityHex`

### Requirement: Client Close does not dispose a shared store
`lapi.Client.Close` and `Sleep` SHALL stop tickers and idle LAPI HTTP only. They MUST NOT call Store `Close`. Only the store’s reclaim Close hook SHALL dispose Redis. Range membership SHALL live on the Store (in-process trees) and SHALL hydrate from the shared `range-index`.

#### Scenario: One Client Close leaves the sibling store live
- **WHEN** two Clients hold the same DecisionStore
- **AND** the first Client `Close`s
- **THEN** the second Client’s Lookup of a previously written ban is still a hit
- **AND** the Redis pool is not closed

### Requirement: Memory engine is copy-on-write maps
A memory-backed Store SHALL hold `map[string]LiveSlot` (packed word and expiresAt), always non-nil. Each `LiveSlot.expiresAt` SHALL be int32 elapsed whole seconds on the package elapsed clock (not wall Unix). BeginTick SHALL clone published into tick. PutMany and DeleteMany during a stream apply SHALL mutate tick only. PublishTick SHALL accept `now` as int32 elapsed seconds on that same clock. When `now` is `0`, memory PublishTick SHALL skip dropping slots by expiry and SHALL still publish tick once (sentinel). When `now` is not `0`, PublishTick SHALL drop tick slots where `expiresAt > 0 && expiresAt <= now`, then publish once. Memory lookup and live PutMany copy-on-write sweeps SHALL use the same elapsed `now` and predicate. Memory MUST NOT Set stream or live Ip or header keys on a TTL heap. When no tick is open, PutMany SHALL copy-on-write onto the published map (live/none memo). Redis BeginTick and PublishTick SHALL be no-ops and SHALL ignore the elapsed `now` argument. Redis PutMany SHALL group by DurationSec and MSetEX in `PutManyChunk` (1024) batches. Redis DeleteMany SHALL DEL each key (SimpleRedis has no multi-DEL).

#### Scenario: Memory stream IP is not on a TTL heap
- **WHEN** stream/alone memory stores an Ip ban for a client address
- **THEN** lookup reads the published LiveSlot map for that Ip key after PublishTick

#### Scenario: Single publish after full payload
- **WHEN** one stream payload adds two Ip bans and deletes one header scope
- **THEN** observers see at most one new map generation for that apply
- **AND** all three mutations appear together after PublishTick

#### Scenario: PublishTick zero skips expiry sweep
- **WHEN** memory PublishTick is called with elapsed `now` `0` while tick holds slots that would expire for a non-zero `now`
- **THEN** those slots remain in the published map after PublishTick
- **AND** a later lookup using elapsed `now` still applies the expiry predicate

### Requirement: Memory slot expiry uses elapsed seconds
The decisionstore package SHALL hold a process-wide `time.Time` origin captured at package load. Elapsed `now()` SHALL be whole seconds of `time.Since` that origin plus two (so `0` stays the PublishTick skip-sweep sentinel), saturated into `[2, MaxInt32]`. That `Since` SHALL use Go's monotonic clock on the origin `Time`; it MUST NOT subtract wall Unix from a stored Unix origin. Packing a memory slot from CrowdSec `durationSec` SHALL set `expiresAt` to a saturated int32 in `[1, MaxInt32]` derived from elapsed `now()` plus `durationSec` (`1` is already expired and still `> 0`), so duration `0` and `-1` yield values that miss under the predicate `expiresAt > 0 && expiresAt <= now()` on the next comparison. The Store `PublishTick` method and the memory engine PublishTick callback SHALL take `now` as int32 elapsed seconds. Callers that drive memory expiry (including stream apply after a payload) SHALL pass elapsed `now()`, not wall Unix seconds.

#### Scenario: Stream apply passes elapsed now
- **WHEN** the stream poller finishes applying one payload on a memory-backed Store
- **THEN** it calls PublishTick with elapsed seconds from the decisionstore clock
- **AND** it does not pass wall Unix seconds as `now`

#### Scenario: Wall Unix now would drop every slot
- **WHEN** published memory slots hold elapsed `expiresAt` values
- **AND** a caller mistakenly passes wall Unix magnitude as PublishTick `now`
- **THEN** the implementation contract treats that as incorrect usage; correct callers use elapsed `now()` only

#### Scenario: Duration zero does not linger past publish sweep
- **WHEN** memory PutMany stores a slot with duration `0` during a tick
- **AND** PublishTick runs with non-zero elapsed `now`
- **THEN** that slot is absent from the published map after PublishTick

### Requirement: Redis engine uses utilities SimpleRedis
The Redis engine SHALL import `github.com/david-garcia-garcia/traefik-middleware-utilities/simpleredis` for GET/SET/DEL/MGET/MSetEX. Runtime SHALL NOT import `github.com/maxlerebourg/simpleredis` and MUST NOT keep `pkg/simpleredis` or `pkg/cache`. `go.mod` SHALL require `github.com/david-garcia-garcia/traefik-middleware-utilities` at `v1.0.7`. Construction SHALL call `simpleredis.New` with Host, Pass, Database, dial 2s and command 1s (idle 30s, pool 8). Writer and readers SHALL be pointers. Commands SHALL pass `context.Background()` when the store API has no request context. After Close, Get/MGET/SET/DEL/MSetEX SHALL surface `store:unreachable` and MUST NOT open a new TCP connection. Close SHALL remain safe to call more than once.

#### Scenario: Redis compiles against utilities SimpleRedis
- **WHEN** a reviewer inspects `pkg/decisionstore/redis.go` and `go.mod`
- **THEN** the Redis engine imports `github.com/david-garcia-garcia/traefik-middleware-utilities/simpleredis`
- **AND** `go.mod` requires that module at `v1.0.7`
- **AND** `pkg/cache` is not the Redis client

### Requirement: Redis Get uses nextReader only
When Redis read hosts are set, Get and MGet SHALL call `nextReader` only. A miss or replica error MUST NOT be retried on the writer. When the reader list is empty, `nextReader` SHALL return the writer.

#### Scenario: Replica miss is not retried on the writer
- **WHEN** Redis has one or more read hosts and Get on the selected reader returns miss
- **THEN** Get returns `store:miss`
- **AND** the writer is not called for that Get

#### Scenario: Replica unreachable is not retried on the writer
- **WHEN** Redis has one or more read hosts and Get on the selected reader is unreachable
- **THEN** Get returns `store:unreachable`
- **AND** the writer is not called for that Get

### Requirement: Redis Set and Delete are void
Redis PutMany and DeleteMany SHALL return no error to callers. Redis MSetEX and DEL SHALL use the writer, log a Redis error, and return. Stream and live callers MUST NOT fail closed on a write miss. Redis MSetEX SHALL send `EX` with the duration integer as given, including `0`. Memory MUST NOT store a slot whose duration is `0` as a lasting published entry beyond PublishTick expiry sweep.

#### Scenario: Redis Set error is logged and discarded
- **WHEN** Redis MSetEX on the writer fails
- **THEN** the error is logged
- **AND** PutMany returns without an error value

#### Scenario: Redis Set with duration 0 sends EX 0
- **WHEN** Redis PutMany is called with DurationSec `0`
- **THEN** the writer sends MSetEX with `EX 0`
- **AND** the write is not skipped

### Requirement: Store errors are miss and unreachable
Store errors SHALL be the package sentinels `ErrMiss` and `ErrUnreachable`. Their `Error()` text SHALL remain `store:miss` and `store:unreachable`. Callers that distinguish miss from unreachable SHALL use `errors.Is`. A clean miss MUST NOT allocate a new error value. Memory and Redis engines SHALL return the same sentinels. Redis SHALL treat utilities miss as `store:miss` and unreachable as `store:unreachable`.

#### Scenario: In-memory miss is the miss sentinel
- **WHEN** a memory Store Lookup of an absent key returns an error
- **THEN** `errors.Is(err, ErrMiss)` is true
- **AND** `err.Error()` is `store:miss`

#### Scenario: Redis unreachable is the unreachable sentinel
- **WHEN** a Redis Store Lookup fails because the store is unreachable
- **THEN** `errors.Is(err, ErrUnreachable)` is true
- **AND** `err.Error()` is `store:unreachable`

### Requirement: DecisionStore owns the origin intern table
A DecisionStore SHALL own a `pkg/intern.Table` (`names []string` index-is-id, `byName` string→`uint16`; empty name is id 0; lock-free `Name` for a known id). CrowdSec `Pack`/`Unpack`/`KindOriginString` SHALL live in `pkg/decisionstore`. The pack word SHALL be `uint32(kind[0]) | uint32(id)<<8 | familyCode<<24` (`familyCode` 1=`ipv4`, 2=`ipv6`, 0=empty). Unpack origin id SHALL be `uint16(word>>8)` so bits 24–25 do not collide. Memory Put SHALL classify family with `FamilyOfHostOrCIDR` on the decision value once. The table MUST NOT be a package variable. Two DecisionStores with different reclaim keys MUST NOT share the table. Intern MUST stay off `lapi.Client` except thin forwards tests need. When intern would overflow `uint16`, the store SHALL log at Warn and SHALL store a kind-only packed word with origin id `0` (generic empty intern name) on memory, and SHALL store `KindOriginString(kind, origin)` on Redis without a leftover U+001F string. Redis slots SHALL be `KindOriginString` (kind, then newline, then origin; bare kind when origin is empty). Memory Ip and header writes SHALL Pack into the word map. Range-index blobs SHALL use `KindOriginString`, never a packed intern id in the blob. `HeaderScopeKey` and `IPCacheKey` SHALL live in `pkg/decisionstore`.

#### Scenario: Memory stream IP write packs the intern id
- **WHEN** stream/alone memory stores an Ip ban whose origin is `crowdsec`
- **THEN** the published word’s low byte is `t` and OriginName of that origin id is `crowdsec`

#### Scenario: Distinct stores do not share intern ids
- **WHEN** two DecisionStores have different reclaim keys and both intern `crowdsec`
- **THEN** each store’s `OriginName` answers only from its own table

#### Scenario: Overflow stores origin id 0
- **WHEN** intern would assign an id past `uint16` max and the store Puts that Ip slot
- **THEN** memory packs the ban or captcha kind with origin id `0`
- **AND** lookup returns the kind without an origin name
- **AND** a Warn is logged
- **AND** Redis does not store a leftover U+001F string for that overflow

### Requirement: Stream and live write TTLs stay split
When stream apply stores a non-Range decision, the store write TTL SHALL be `int64` of the parsed CrowdSec duration in seconds, with no clamp. A sub-second duration SHALL become `0`. Live and none writes SHALL use `liveCacheTTL`: when `durationSecond<=0` or `defaultDecisionSeconds` is smaller than `durationSecond`, the write TTL SHALL be `defaultDecisionSeconds`; otherwise it SHALL be `durationSecond`. Stream MUST NOT use `liveCacheTTL`. Live and none MUST NOT pass raw `Seconds()` without that substitution.

#### Scenario: Stream sub-second duration becomes 0
- **WHEN** stream apply parses a CrowdSec duration shorter than one second
- **THEN** the Store Put duration is `0`

#### Scenario: Live non-positive duration uses the default
- **WHEN** a live write has `durationSecond<=0` and a positive `defaultDecisionSeconds`
- **THEN** the Store Put duration is `defaultDecisionSeconds`

#### Scenario: Stream does not substitute the live default
- **WHEN** stream apply parses a duration of `0s`
- **THEN** the Store Put duration is `0`
- **AND** `liveCacheTTL` is not used

### Requirement: Request lookup is Store LookupRemediation
Stream/alone and live/none request lookup SHALL call `Store.LookupRemediation(remoteIP, ipAddr, scopes)` and SHALL merge Ip, present header scopes, and Range membership with ban-wins (`PreferRemediation` in `decisionscope`). Unexported `lookupHits` and `lookupKeys` SHALL live in `decisionstore`. Memory SHALL probe published maps; Redis SHALL MGet the lookup keys. When the Ip probe is an active ban, lookup MAY skip Range membership. Lookup MUST NOT call `GetInt` then leftover `Get`, MUST NOT use `LookupStreamMapRemediation`, and MUST NOT concat-then-split kind and origin. Persistence, pack, and Range membership MUST NOT live in `decisionscope`.

#### Scenario: Memory miss probes without a TTL heap
- **WHEN** stream/alone memory has no Ip ban for the client address
- **THEN** lookup completes without a TTL-heap Get of that Ip key
- **AND** Range membership is still consulted when Ip is not an active ban

#### Scenario: Memory Ip ban skips Range
- **WHEN** stream/alone memory holds an Ip ban for the client and Range membership would captcha
- **THEN** the merged result is ban

#### Scenario: Lookup miss is the miss sentinel
- **WHEN** `LookupRemediation` finds no active remediation and the Ip key is absent
- **THEN** the returned error satisfies `errors.Is(err, ErrMiss)`

### Requirement: Range blob is cidr equals kind then origin on the next line
`range-index` SHALL be one key whose records are a `cidr=kind` line and, when origin is non-empty, the origin on the following newline line (a line that does not contain `=`). Packed intern ids MUST NOT appear in that blob. `ApplyRangeBatch` SHALL keep one read, removals then upserts, and one write; a failed GET that is not a miss SHALL still return and MUST NOT write. In-process Range membership SHALL rebuild from that blob onto ban and captcha Helpers and SHALL return the stored `KindOriginString` of the winning CIDR (ban over captcha; longest-prefix matching ban). `atomic.Value` SHALL hold `*RangeMembership`. A ticker that skips LAPI SHALL still hydrate when the blob changed.

#### Scenario: Range line with origin remediates
- **WHEN** `range-index` holds `10.0.0.0/8=t` then a newline and `crowdsec` and the client IP is `10.1.2.3`
- **THEN** the request is banned and lookup origin is `crowdsec`

#### Scenario: Bare Range kind still remediates
- **WHEN** `range-index` holds only `10.0.0.0/8=t` and the client IP is `10.1.2.3`
- **THEN** the request is banned

#### Scenario: Unreachable read preserves the shared index
- **WHEN** RangeIndex answers `store:unreachable` and a poll would upsert a new Range CIDR
- **THEN** `ApplyRangeBatch` returns the error and the stored `range-index` still holds the CIDRs it held before

### Requirement: DecisionStore owns the active-decision group-by
A DecisionStore SHALL expose `ActiveCounts` as a snapshot copy of `{originID uint16, family} → int64` for Ip and header-scope slots. The gauge is the engine's job. Memory SHALL recount from the published LiveSlot map after PublishTick builds that snapshot (including after the elapsed-expiry sweep when `now` is not `0`). PutMany, DeleteMany, and live copy-on-write MUST NOT increment or decrement a running map. Live/none memo Put MUST NOT PublishTick, so `ActiveCounts` SHALL stay empty. Range MUST NOT be counted: `ApplyRangeBatch` MUST NOT appear in the published LiveSlot walk; the store MUST NOT Peek membership or query Range Helper Contains for metrics. Redis `ActiveCounts` SHALL be empty: per-key SET has no slot inventory, and SCAN+MGET or a HASH of slots would be a storage redesign only for this gauge. Overwrite of an existing canonical slot SHALL appear as the last origin after the next memory PublishTick. A prior-spelling extra DEL MUST NOT be a second gauge event. `ActiveCounts` MUST NOT expose `usageMetricKey` or LAPI item JSON. Family SHALL be the packed family code from that word (`FamilyOfHostOrCIDR` at memory Put on the decision value; header-scope Country/AS POST empty `ip_type`). The PublishTick walk MUST NOT parse the slot key. Intern overflow SHALL count origin id `0`. Dispatch MUST NOT add a Go engine interface for this gauge.

#### Scenario: Stream Ip Put increments the compact map
- **WHEN** a memory store Puts one Ip ban whose value is `1.2.3.4` and origin is `crowdsec` during a tick
- **AND** PublishTick runs
- **THEN** `ActiveCounts` includes 1 for that origin id and `ipv4`

#### Scenario: Stream IPv6 Put uses packed family
- **WHEN** a memory store Puts one Ip ban whose value is `2001:db8::1` during a tick
- **AND** PublishTick runs
- **THEN** `ActiveCounts` includes 1 for that origin id and `ipv6`

#### Scenario: Stream Ip Delete decrements
- **WHEN** that same store later Deletes that Ip slot during a tick
- **AND** PublishTick runs
- **THEN** `ActiveCounts` omits that group (or the count is 0)

#### Scenario: Live Put does not increment
- **WHEN** a store Puts a memo Ip ban without PublishTick
- **THEN** `ActiveCounts` is empty

#### Scenario: Range apply does not increment
- **WHEN** stream ApplyRangeBatch upserts a Range CIDR
- **THEN** `ActiveCounts` does not include that CIDR

#### Scenario: Memory PublishTick expiry drops the slot
- **WHEN** a memory store holds an Ip slot whose elapsed expiry is due
- **AND** PublishTick runs with non-zero elapsed `now`
- **THEN** `ActiveCounts` omits that slot

#### Scenario: Redis ActiveCounts is empty
- **WHEN** a Redis store Puts or Deletes Ip slots
- **THEN** `ActiveCounts` is empty

#### Scenario: Overflow counts origin id 0
- **WHEN** intern would overflow and a memory store Puts an Ip slot then PublishTick runs
- **THEN** `ActiveCounts` keys that slot with origin id `0`
