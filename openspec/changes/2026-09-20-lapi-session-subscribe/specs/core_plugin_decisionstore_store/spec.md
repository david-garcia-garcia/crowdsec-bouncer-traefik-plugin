## ADDED Requirements

### Requirement: DecisionStore is a child of Client create
A DecisionStore SHALL be `pkg/decisionstore.Store`, constructed only inside `lapi.Client` `create()` with `NewMemory` or `NewRedis` and Redis `keyPrefix` = `SessionHex`. `OpenStream` / `OpenLive` MUST NOT Open a DecisionStore on the constructor ctx as a sibling reclaim value. `StoreKey` MAY remain as a composition helper; it MUST NOT be a sibling reclaim Open for this Client’s store. If `create()` fails after constructing a store, it SHALL Close that store before returning the error. The store SHALL bind engine funcs at `NewMemory` or `NewRedis` (`memoryEngine` / `redisEngine`): BeginTick, PublishTick, Put, Delete, LookupRemediation, ApplyRangeBatch, RangeIndex, Close. A constructed Store SHALL always have those callbacks. Store methods MUST NOT nil-check `s` or the engine funcs. Close SHALL be safe to call more than once on a real Redis store; tests MUST NOT Close a nil `*Store`. Dispatch MUST NOT be a backend interface and MUST NOT branch `if mem` / `if red` on every method. Yaegi-safe: the engine MUST NOT put a map-holding type in an interface; primitive `map[string]uint32` and `map[string]int64` SHALL always be non-nil; intern SHALL be `[]string` plus `map[string]uint16`; `atomic.Value` SHALL hold only `*RangeMembership` and `string`. The store MUST NOT install Sleep or Wake. The package MUST NOT keep a process-wide map or a `sync.Once`. Callers MUST NOT import utilities `reclaim`. There SHALL NOT be a second `liveStore` type: live/none memo is Store Put and Lookup. `pkg/cache` MUST NOT exist as the DecisionStore bag. Client address, when this leaf mentions it, SHALL reuse `pkg/ip.GetRemoteIP`. CrowdSec cursor identity SHALL reuse `SessionHex` / `streamSession`. Two stream Clients that share a LAPI session SHALL share that child store (first-wins Redis YAML). Two live or none Clients that differ on Redis store parameters SHALL each construct their own store. Two live or none Clients that differ only on `metricsUpdateIntervalSeconds` SHALL each construct their own store; memory backends isolate; Redis backends still share keys via `SessionHex`.

#### Scenario: Interval mismatch still shares one store
- **WHEN** two live `New` calls use the same LAPI URL and key and the same Redis store parameters and differ only on `updateIntervalSeconds`
- **THEN** both expose the same Store incarnation
- **AND** a ban written by the first is a hit for the second

#### Scenario: Stream Redis disagreement keeps one store
- **WHEN** two stream `New` calls share LAPI URL and key and use different `redisCacheHost`
- **THEN** one DecisionStore incarnation exists
- **AND** a ban written by the first is a hit for the second

#### Scenario: Live different Redis hosts are isolated stores
- **WHEN** two live `New` calls share LAPI URL and key and use different `redisCacheHost`
- **THEN** two DecisionStore incarnations exist
- **AND** a ban present only in the first store is a miss on the second

#### Scenario: Header-map mismatch still shares remediations
- **WHEN** two stream Clients share LAPI URL and key and differ only on `decisionScopeHeaders`
- **THEN** they use the same DecisionStore
- **AND** an IP ban written by the first is a hit for the second

#### Scenario: Live metrics-interval split does not share a reclaim store
- **WHEN** two none `New` calls use the same LAPI URL, key, and Redis store parameters and differ only on `metricsUpdateIntervalSeconds`
- **THEN** two DecisionStore incarnations exist
- **AND** on a memory backend a ban written by the first is a miss on the second

#### Scenario: Redis Close twice is safe
- **WHEN** a constructed Redis Store Close runs twice
- **THEN** the second Close does not panic
- **AND** later Lookup is unreachable

### Requirement: Client Close Closes the child store
`lapi.Client.Close` SHALL Close the child DecisionStore after tickers and idle LAPI HTTP. `Sleep` and `Wake` MUST NOT call Store `Close`. Range membership SHALL live on the Store (in-process trees) and SHALL hydrate from the shared `range-index`.

#### Scenario: Last Client holder Close drains Redis
- **WHEN** the last constructor context bound to a LAPI Client is cancelled and grace elapses
- **THEN** Redis `Close` runs once
- **AND** a later Lookup on that closed Redis store is unreachable

#### Scenario: Sleep keeps the store
- **WHEN** the last constructor context bound to a LAPI Client is cancelled and the slot is sleeping
- **THEN** Store Close has not run
- **AND** Lookup of a previously written ban is still a hit

## REMOVED Requirements

### Requirement: DecisionStore is a reclaim value that owns the engine
**Reason**: DecisionStore is no longer a sibling reclaim Open on the Traefik `New` ctx; it is constructed in Client `create()`.
**Migration**: Use ADDED requirement "DecisionStore is a child of Client create".

### Requirement: Store key is cursor plus Redis store parameters
**Reason**: There is no sibling store reclaim key. Redis logical keys stay under `SessionHex` (existing "Redis prefix is SessionHex for every mode").
**Migration**: `StoreKey` MAY remain a helper; do not Open it. Stream Redis disagreement shares the child store. Live Redis disagreement still splits live `Key`.

### Requirement: Client Close does not dispose a shared store
**Reason**: Sibling store share is gone. The Client Close hook owns Store Close.
**Migration**: Use ADDED requirement "Client Close Closes the child store".
