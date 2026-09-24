## MODIFIED Requirements

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
