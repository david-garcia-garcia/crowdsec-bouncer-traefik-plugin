## Purpose\n\nThe store that holds CrowdSec Ip, header, and Range decisions on a memory or Redis engine. One Store is a child of one `lapi.Client` incarnation.\n\n## Requirements\n\n### Requirement: DecisionStore is a reclaim value that owns the engine
A DecisionStore SHALL be `pkg/decisionstore.Store`, opened with `reclaim.OpenWithHooks` on the process table using the same Traefik `New` context as `lapi.OpenStream` / `OpenLive`. The store SHALL bind engine funcs at `NewMemory` or `NewRedis` (`memoryEngine` / `redisEngine`): BeginTick, PublishTick, Put, Delete, LookupRemediation, ApplyRangeBatch, RangeIndex, Close. A constructed Store SHALL always have those callbacks. Store methods MUST NOT nil-check `s` or the engine funcs. Close SHALL be safe to call more than once on a real Redis store; tests MUST NOT Close a nil `*Store`. Dispatch MUST NOT be a backend interface and MUST NOT branch `if mem` / `if red` on every method. Yaegi-safe: the engine MUST NOT put a map-holding type in an interface; primitive `map[string]uint32` and `map[string]int64` SHALL always be non-nil; intern SHALL be `[]string` plus `map[string]uint16`; `atomic.Value` SHALL hold only `*RangeMembership` and `string`. The store MUST NOT install Sleep or Wake. The package MUST NOT keep a process-wide map or a `sync.Once`. Callers MUST NOT import utilities `reclaim`. There SHALL NOT be a second `liveStore` type: live/none memo is Store Put and Lookup. `pkg/cache` MUST NOT exist as the DecisionStore bag. Client address, when this leaf mentions it, SHALL reuse `pkg/ip.GetRemoteIP`. CrowdSec cursor identity SHALL reuse `SessionHex` / `streamSession`.

#### Scenario: Interval mismatch still shares one store
- **WHEN** two live `New` calls use the same LAPI URL and key and the same Redis store parameters and differ only on `updateIntervalSeconds`
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

### Requirement: Store key is cursor plus Redis store parameters
The DecisionStore reclaim key SHALL be `decisionstore:` plus `SessionHex` (mode, LAPI scheme/host/path, lapiKey, CAPI machine+password) plus a hash of Redis store parameters (`RedisCacheEnabled`, host, read hosts, password, database). That key MUST NOT include `updateIntervalSeconds`, `metricsUpdateIntervalSeconds`, `updateMaxFailure`, `decisionScopeHeaders`, TLS, failure action, `StreamStartupBlock`, live-cache TTL, or middleware name. Stream `scopes=` and the store header-scope filter are owned by `core_plugin_lapi_scope-union`. SessionHex and these Redis store parameters MUST NOT change in this change; existing Redis keys stay reachable.

#### Scenario: Different Redis hosts are isolated stores
- **WHEN** two stream Clients share LAPI URL and key and use different `redisCacheHost`
- **THEN** two DecisionStore incarnations exist
- **AND** a ban present only in the first store is a miss on the second

#### Scenario: Header-map mismatch still shares remediations
- **WHEN** two stream Clients share LAPI URL, key, and Redis store parameters and differ only on `decisionScopeHeaders`
- **THEN** they Open the same DecisionStore
- **AND** an IP ban written by the first is a hit for the second

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
A memory-backed Store SHALL hold `map[string]uint32` (packed word) and `map[string]int64` (expiresAt), always non-nil. BeginTick SHALL clone published maps into tick. Put and Delete during a stream apply SHALL mutate tick only. PublishTick SHALL drop expired tick slots by `expiresAt` and publish once. Memory MUST NOT Set stream or live Ip or header keys on a TTL heap. When no tick is open, Put SHALL copy-on-write onto the published maps (live/none memo). Redis BeginTick and PublishTick SHALL be no-ops.

#### Scenario: Memory stream IP is not on a TTL heap
- **WHEN** stream/alone memory stores an Ip ban for a client address
- **THEN** lookup reads the published word map for that Ip key after PublishTick

#### Scenario: Single publish after full payload
- **WHEN** one stream payload adds two Ip bans and deletes one header scope
- **THEN** observers see at most one new map generation for that apply
- **AND** all three mutations appear together after PublishTick

### Requirement: Redis engine uses utilities SimpleRedis
The Redis engine SHALL import `github.com/david-garcia-garcia/traefik-middleware-utilities/simpleredis` for GET/SET/DEL/MGET. Runtime SHALL NOT import `github.com/maxlerebourg/simpleredis` and MUST NOT keep `pkg/simpleredis` or `pkg/cache`. `go.mod` SHALL require `github.com/david-garcia-garcia/traefik-middleware-utilities` at `v1.0.5`. Construction SHALL call `simpleredis.New` with Host, Pass, Database, dial 2s and command 1s (idle 30s, pool 8). Writer and readers SHALL be pointers. Commands SHALL pass `context.Background()` when the store API has no request context. After Close, Get/MGET/SET/DEL SHALL surface `store:unreachable` and MUST NOT open a new TCP connection. Close SHALL remain safe to call more than once.

#### Scenario: Redis compiles against utilities SimpleRedis
- **WHEN** a reviewer inspects `pkg/decisionstore/redis.go` and `go.mod`
- **THEN** the Redis engine imports `github.com/david-garcia-garcia/traefik-middleware-utilities/simpleredis`
- **AND** `go.mod` requires that module at `v1.0.5`
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
Redis Put and Delete SHALL return no error to callers. Redis SET and DEL SHALL use the writer, log a Redis error, and return. Stream and live callers MUST NOT fail closed on a write miss. Redis SET SHALL send `SET EX` with the duration integer as given, including `0`. Memory MUST NOT store a slot whose duration is `0` as a lasting published entry beyond PublishTick expiry sweep.

#### Scenario: Redis Set error is logged and discarded
- **WHEN** Redis SET on the writer fails
- **THEN** the error is logged
- **AND** Put returns without an error value

#### Scenario: Redis Set with duration 0 sends EX 0
- **WHEN** Redis Put is called with DurationSec `0`
- **THEN** the writer sends `SET` with `EX 0`
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
A DecisionStore SHALL own a `pkg/intern.Table` (`names []string` index-is-id, `byName` string→`uint16`; empty name is id 0; lock-free `Name` for a known id). CrowdSec `Pack`/`Unpack`/`KindOriginString` SHALL live in `pkg/decisionstore`. The pack word SHALL be `uint32(kind[0]) | uint32(id)<<8`. The table MUST NOT be a package variable. Two DecisionStores with different reclaim keys MUST NOT share the table. Intern MUST stay off `lapi.Client` except thin forwards tests need. When intern would overflow `uint16`, the store SHALL log at Warn and SHALL store a kind-only packed word with origin id `0` (generic empty intern name) on memory, and SHALL store `KindOriginString(kind, origin)` on Redis without a leftover U+001F string. Redis slots SHALL be `KindOriginString` (kind, then newline, then origin; bare kind when origin is empty). Memory Ip and header writes SHALL Pack into the word map. Range-index blobs SHALL use `KindOriginString`, never a packed intern id in the blob. `HeaderScopeKey` and `IPCacheKey` SHALL live in `pkg/decisionstore`.

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
