## MODIFIED Requirements

### Requirement: DecisionStore is a reclaim value that owns the cache
A DecisionStore SHALL own one `cache.Client` and SHALL be opened with `reclaim.OpenWithHooks` on the process table using the same Traefik `New` context as `lapi.OpenStream` / `OpenLive`. The store’s reclaim hooks SHALL be Close only (`cache.Client.Close()`). The store MUST NOT install Sleep or Wake (it has no ticker). The package MUST NOT keep a process-wide cache map or a `sync.Once`. Callers MUST NOT import utilities `reclaim`. Client address, when this leaf mentions it, SHALL reuse `pkg/ip.GetRemoteIP` (do not parse `RemoteAddr`). CrowdSec cursor identity SHALL reuse `SessionHex` / `streamSession` (do not reconstruct the LAPI hop).

#### Scenario: Interval mismatch still shares one store
- **WHEN** two live `New` calls use the same LAPI URL and key and the same Redis store parameters and differ only on `updateIntervalSeconds`
- **THEN** both expose the same cache incarnation
- **AND** a ban written by the first is a hit for the second

#### Scenario: Last store holder Close drains Redis
- **WHEN** the last constructor context bound to a DecisionStore key is cancelled and grace elapses
- **THEN** `cache.Client.Close()` runs once
- **AND** a later Get on that closed Redis store is unreachable

### Requirement: Store key is cursor plus Redis store parameters
The DecisionStore reclaim key SHALL be `decisionstore:` plus `SessionHex` (mode, LAPI scheme/host/path, lapiKey, CAPI machine+password) plus a hash of Redis store parameters (`RedisCacheEnabled`, host, read hosts, password, database). That key MUST NOT include `updateIntervalSeconds`, `metricsUpdateIntervalSeconds`, `updateMaxFailure`, `decisionScopeHeaders`, TLS, failure action, `StreamStartupBlock`, live-cache TTL, or middleware name. Stream `scopes=` and the store header-scope filter are owned by `core_plugin_lapi_scope-union`. This leaf MUST NOT keep first-wins `scopes=` or warn-and-wire on the Client reclaim key. SessionHex and these Redis store parameters MUST NOT change in this change; existing Redis keys stay reachable.

#### Scenario: Different Redis hosts are isolated stores
- **WHEN** two stream Clients share LAPI URL and key and use different `redisCacheHost`
- **THEN** two DecisionStore incarnations exist
- **AND** a ban present only in the first store is a miss on the second

#### Scenario: Header-map mismatch still shares remediations
- **WHEN** two stream Clients share LAPI URL, key, and Redis store parameters and differ only on `decisionScopeHeaders`
- **THEN** they Open the same DecisionStore
- **AND** an IP ban written by the first is a hit for the second
