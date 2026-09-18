## Purpose

One DecisionStore reclaim value owns the cache map (memory TTL or Redis-protocol prefix) so LAPI Clients that share a CrowdSec cursor and store parameters share remediations without sharing a poller.

## Requirements

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

### Requirement: Cache prefix is SessionHex for every mode
When Redis is enabled, every GET/SET/DEL/MGET/Eval key the store sends SHALL be prefixed with `SessionHex` of that cursor. Live/none MUST NOT use `IdentityHex` as the prefix. Memory backends SHALL ignore the prefix string and isolate by owning the store’s map. Two stores that share a Redis host and different prefixes MUST NOT observe each other’s decisions or the stream lease key.

#### Scenario: Same Redis host two store prefixes
- **WHEN** two DecisionStores share one Redis-protocol host and different `SessionHex` prefixes
- **AND** the first sets a banned IP
- **THEN** the second’s get of that IP is a miss

#### Scenario: Live prefix is SessionHex not IdentityHex
- **WHEN** a live Client Opens a DecisionStore
- **THEN** Redis keys use `SessionHex` as the prefix
- **AND** that prefix is not `IdentityHex`

### Requirement: Client Close does not dispose a shared store
`lapi.Client.Close` and `Sleep` SHALL stop tickers and idle LAPI HTTP only. They MUST NOT call `cache.Client.Close()`. `Cache()` SHALL still return the shared `cache.Client` for Get/Set. Only the store’s reclaim Close hook SHALL dispose the cache. Range membership SHALL stay on the Client (in-process trees) and SHALL hydrate from the shared `range-index`.

#### Scenario: One Client Close leaves the sibling cache live
- **WHEN** two Clients hold the same DecisionStore
- **AND** the first Client `Close`s
- **THEN** the second Client’s `Cache().Get` of a previously written ban is still a hit
- **AND** the Redis pool is not closed

### Requirement: Cache payloads stay opaque strings
A cache Client SHALL store and return opaque strings. The cache package MUST NOT export CrowdSec remediation names (`BannedValue`, `CaptchaValue`, `NoBannedValue`). Store errors SHALL remain `CacheMiss` and `CacheUnreachable`.

#### Scenario: Cache tests treat values as opaque
- **WHEN** a cache test Sets and Gets a payload
- **THEN** it uses a string literal, not a decisionscope or captcha const

### Requirement: Stream and live write TTLs stay split
When stream apply stores a non-Range decision, the store write TTL SHALL be `int64` of the parsed CrowdSec duration in seconds, with no clamp. A sub-second duration SHALL become `0`. Live and none writes SHALL use `liveCacheTTL`: when `durationSecond<=0` or `defaultDecisionSeconds` is smaller than `durationSecond`, the write TTL SHALL be `defaultDecisionSeconds`; otherwise it SHALL be `durationSecond`. Stream MUST NOT use `liveCacheTTL`. Live and none MUST NOT pass raw `Seconds()` without that substitution.

#### Scenario: Stream sub-second duration becomes 0
- **WHEN** stream apply parses a CrowdSec duration shorter than one second
- **THEN** the DecisionStore Set duration is `0`

#### Scenario: Live non-positive duration uses the default
- **WHEN** a live write has `durationSecond<=0` and a positive `defaultDecisionSeconds`
- **THEN** the DecisionStore Set duration is `defaultDecisionSeconds`

#### Scenario: Stream does not substitute the live default
- **WHEN** stream apply parses a duration of `0s`
- **THEN** the DecisionStore Set duration is `0`
- **AND** `liveCacheTTL` is not used
