## Purpose

How a shared LAPI Client builds stream `scopes=` and the stream store filter from the union of live routers’ normalized header-scope maps, without mutating write-once `decisionScopeHeaders`.

## ADDED Requirements

### Requirement: Stream scopes are the live-router union
A stream or alone `lapi.Client` SHALL hold a Client-owned registry of header-scope maps from each live constructor that bound that Client. After a successful `OpenStream` bind, the constructor SHALL register this `New` ctx and this router’s normalized `decisionScopeHeaders`. When that ctx is Done, the Client SHALL drop that registration. `streamQuery` and `storeStreamDecision` SHALL snapshot the union of registered maps under the existing Client mutex. The write-once `decisionScopeHeaders` field set in `New` MUST NOT become mutable and MUST NOT be the live union. Implementations MUST NOT use `atomic.Pointer[T]`, `sync.Once`, or a package global for this registry. CAPI (alone) SHALL still omit `scopes=`. Live and none SHALL keep passing scopes per `LiveLookup` from the bouncer map. AppSec reclaim key is unchanged. Client address, when this leaf mentions it, SHALL reuse `pkg/ip.GetRemoteIP` (do not parse `RemoteAddr`).

#### Scenario: Two routers union Country and username
- **WHEN** two live stream `New` calls share one Client and one maps `Country` while the other maps `username`
- **THEN** the next LAPI stream query includes both `country` and `username` in `scopes=`
- **AND** a streamed `username` decision is stored
- **AND** a streamed `Country` decision is stored

#### Scenario: Unregister drops a scope from the next query
- **WHEN** the constructor ctx that registered `username` is cancelled and the other holder still maps `Country`
- **THEN** a later stream query includes `country` and does not include `username`

#### Scenario: Empty union streams only ip and range
- **WHEN** every live holder’s normalized header map is empty
- **THEN** the stream query does not include `country`

### Requirement: Growing the union does not send startup=true
When a later live router registers a header scope after the CrowdSec cursor has advanced, the Client MUST NOT send `startup=true` for that registration. LAPI `scopes=` is a filter of `id_gt`; a newly added scope misses decisions already past the cursor until a later incarnation `startup=true`.

#### Scenario: Late Country join misses prior Country bans
- **WHEN** a stream Client has already polled with `startup=false` after a Country ban’s id
- **AND** a later live router registers `Country`
- **THEN** the next stream query includes `country` and uses `startup=false`
- **AND** that already-passed Country ban is not backfilled by this registration

### Requirement: Shrinking the union does not sweep cache keys
When a registration is dropped, the Client MUST NOT sweep header-scope cache keys. Stale Country/AS keys expire with TTL or die with the store incarnation.

#### Scenario: Unregister leaves an existing Country key
- **WHEN** the store holds a Country ban key and the last `Country` registration is dropped
- **THEN** that cache key is not deleted by unregister
