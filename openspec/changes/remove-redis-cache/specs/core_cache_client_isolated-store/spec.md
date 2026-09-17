## ADDED Requirements

### Requirement: Cache is memory-only per Client
The plugin SHALL construct cache Clients that store keys only in a map owned by that Client. The cache package MUST NOT offer a Redis or other cross-process backend. Each Traefik replica and each distinct LAPI Client SHALL hold its own remediations and stream lease keys in that process.

#### Scenario: No shared store across processes
- **WHEN** two Traefik processes serve the same LAPI URL and API key with stream mode
- **THEN** each process maintains its own cache map
- **AND** a stream lease key `updated` in one process does not suppress LAPI polling in the other

### Requirement: Stream lease isolation matches LAPI bouncer rows
Stream poll lease keys SHALL remain in the isolated cache space of the LAPI Client that owns that CrowdSec bouncer row (hashed API key plus outbound IP LAPI sees). The product MUST NOT treat a lease written by another process as authoritative for skipping LAPI stream fetch.

#### Scenario: Distinct outbound IPs both poll
- **WHEN** two replicas use the same LAPI URL and key but LAPI assigns distinct bouncer rows because their outbound IPs differ
- **THEN** each replica performs its own stream fetch when its lease is absent
- **AND** neither replica skips polling solely because another replica stored `updated`

## MODIFIED Requirements

### Requirement: Memory cache is per Client not process-wide
A cache Client SHALL store keys in a map owned by that Client. The package MUST NOT keep a process-wide TTL map shared by all Clients.

#### Scenario: Two memory clients do not leak
- **WHEN** Client A sets key `1.2.3.4` to banned
- **AND** Client B is a different Client in the same process
- **THEN** Client B’s get of `1.2.3.4` is a miss

### Requirement: Cache payloads are opaque strings
A cache Client SHALL store and return opaque strings. The cache package MUST NOT export CrowdSec remediation names (`BannedValue`, `CaptchaValue`, `NoBannedValue`). Store errors SHALL remain `CacheMiss` and `CacheUnreachable`. Isolated key spaces SHALL remain per Client memory map.

#### Scenario: Cache tests treat values as opaque
- **WHEN** a cache test Sets and Gets a payload
- **THEN** it uses a string literal, not a decisionscope or captcha const

## REMOVED Requirements

### Requirement: Redis keys are prefixed with session identity for stream
**Reason**: Redis cache backend removed; cross-replica shared lease broke LAPI per-row stream cursors.
**Migration**: Remove `redisCache*` from Traefik config; each replica polls LAPI and caches locally. No key migration.
