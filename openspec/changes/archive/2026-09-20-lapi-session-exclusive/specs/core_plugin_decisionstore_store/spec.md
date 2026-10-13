## MODIFIED Requirements

### Requirement: DecisionStore is a reclaim value that owns the engine
A DecisionStore SHALL be `pkg/decisionstore.Store`, opened with `reclaim.OpenWithHooks` on the process table using the same Traefik `New` context as `lapi.OpenStream` / `OpenLive`. Callers SHALL Peek that store key before Open (`core_plugin_lapi_reclaim-key`). `lapi.OpenDecisionStore` SHALL take the Traefik name so create() can write `createdBy`. The store SHALL bind engine funcs at `NewMemory` or `NewRedis` (`memoryEngine` / `redisEngine`): BeginTick, PublishTick, PutMany, DeleteMany, LookupRemediation, ApplyRangeBatch, RangeIndex, Close. Put and Delete SHALL be one-item wrappers around PutMany and DeleteMany. A constructed Store SHALL always have those callbacks. Store methods MUST NOT nil-check `s` or the engine funcs. Close SHALL be safe to call more than once on a real Redis store; tests MUST NOT Close a nil `*Store`. Dispatch MUST NOT be a backend interface and MUST NOT branch `if mem` / `if red` on every method. Yaegi-safe: the engine MUST NOT put a map-holding type in an interface; `map[string]LiveSlot` SHALL always be non-nil; intern SHALL be `[]string` plus `map[string]uint16`; Store `atomic.Value` SHALL hold only `*RangeMembership` and `string`. Memory published slots SHALL be `atomic.Value` of `*publishedSlots` (not the map). Memory `LookupRemediation` MUST NOT take `mu`; writers still `Lock` to clone and Store. The store MUST NOT install Sleep or Wake. The package MUST NOT keep a process-wide map or a `sync.Once`. Callers MUST NOT import utilities `reclaim`. There SHALL NOT be a second `liveStore` type: live/none memo is Store Put and Lookup. `pkg/cache` MUST NOT exist as the DecisionStore bag. Client address, when this leaf mentions it, SHALL reuse `pkg/ip.GetRemoteIP`. CrowdSec cursor identity SHALL reuse `SessionHex` / `streamSession`.

#### Scenario: Interval mismatch still shares one store
- **WHEN** two live `New` calls use the same Traefik name, the same LAPI URL and key, and the same Redis store parameters and differ only on `updateIntervalSeconds`
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

## REMOVED Requirements

### Requirement: Store key is cursor plus Redis store parameters
**Reason**: The store is the session lock keyed by CrowdSec cursor `SessionHex`. Redis YAML change reuses the existing engine (first-wins) instead of isolating a second store. Exclusive ownership is write-once `createdBy`, not a Redis hash.
**Migration**: The DecisionStore reclaim key is `decisionstore:` plus `SessionHex` only. Client Open keys may still hash Redis store parameters.

## ADDED Requirements

### Requirement: Store key is SessionHex only
The DecisionStore reclaim key SHALL be `decisionstore:` plus `SessionHex` (mode, LAPI scheme/host/path, lapiKey, CAPI machine+password). That key MUST NOT include a hash of Redis store parameters (`RedisCacheEnabled`, host, read hosts, password, database), `updateIntervalSeconds`, `metricsUpdateIntervalSeconds`, `updateMaxFailure`, `decisionScopeHeaders`, TLS, failure action, `StreamStartupBlock`, live-cache TTL, or middleware name. Stream `scopes=` and the store header-scope filter are owned by `core_plugin_lapi_scope-union`. SessionHex MUST NOT change in this change; existing Redis keys stay reachable. A Redis YAML change (host, enabled, password, database, read hosts) with the same Traefik name SHALL Open the existing store and MUST NOT replace the engine already bound at create() (first-wins memory vs Redis).

#### Scenario: Different Redis hosts share one store
- **WHEN** two stream Clients share Traefik name, LAPI URL and key and use different `redisCacheHost`
- **THEN** one DecisionStore incarnation exists
- **AND** a ban written by the first is a hit for the second

#### Scenario: Header-map mismatch still shares remediations
- **WHEN** two stream Clients share Traefik name, LAPI URL, and key and differ only on `decisionScopeHeaders`
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
