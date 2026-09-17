## Purpose

Each Crowdsec connection’s cache Client has an isolated key space so two **sessions** in one process cannot read or write each other’s remediations or stream lease. Stream/alone middlewares that share a LAPI session share one Client (one prefix).

## Requirements

### Requirement: Memory cache is per Client not process-wide
When redis is disabled, a cache Client SHALL store keys in a map owned by that Client. The package MUST NOT keep a process-wide TTL map shared by all Clients.

#### Scenario: Two memory clients do not leak
- **WHEN** Client A sets key `1.2.3.4` to banned
- **AND** Client B is a different Client in the same process
- **THEN** Client B’s get of `1.2.3.4` is a miss

### Requirement: Redis keys are prefixed with session identity for stream
When redis is enabled, every GET/SET/DEL key the cache sends SHALL be prefixed. For stream/alone the prefix base SHALL be the stream session hex (LAPI URL+key), not leftover extras (intervals; Redis host is the Client’s target, not the prefix). For live/none the prefix base SHALL remain the full connection identity hex. The full prefix SHALL append one `:` and the sanitized effective bouncer instance identity after that base. Two Clients that share a Redis host and different full prefixes MUST NOT observe each other’s decisions or the stream lease key. Two Clients on the same process that share a LAPI session and the same effective instance identity SHALL share one prefix (warn-and-wire).

#### Scenario: Same Redis host two prefixes
- **WHEN** two Clients share one Redis-protocol host and different full prefixes
- **AND** the first sets a banned IP
- **THEN** the second’s get of that IP is a miss

#### Scenario: Same session same instance one prefix
- **WHEN** two stream middlewares on one process share a LAPI session and instance identity
- **THEN** they share one Redis prefix and one stream lease key space

#### Scenario: Same session different instances isolated
- **WHEN** two processes share one Redis host and the same LAPI session hex base but different effective instance identities
- **THEN** neither process reads or writes the other’s stream lease key `updated`

### Requirement: Stream lease is per stream session
The stream poller lease key SHALL live in that connection’s isolated cache space (full Redis prefix including instance identity when Redis is enabled). Two stream **sessions** (different LAPI URL or key) MUST NOT skip a poll because the other wrote the lease. Two stream middlewares on the **same** session and **same** bouncer instance share one lease and one poller. Two bouncer instances MUST NOT treat another instance’s lease as their own even when they share LAPI URL, API key, and Redis host.

#### Scenario: Two stream sessions both poll
- **WHEN** two stream-mode connections exist in one process for different LAPI hosts
- **THEN** each performs its own stream fetch against its own LAPI
- **AND** neither treats the other’s lease as its own

#### Scenario: Two instances same LAPI session both poll
- **WHEN** two processes share Redis and the same LAPI URL and API key but have different effective instance identities
- **THEN** each process performs stream fetches according to its own lease key
- **AND** neither skips LAPI solely because the other instance holds `updated`

### Requirement: Cache payloads are opaque strings
A cache Client SHALL store and return opaque strings. The cache package MUST NOT export CrowdSec remediation names (`BannedValue`, `CaptchaValue`, `NoBannedValue`). Store errors SHALL remain `CacheMiss` and `CacheUnreachable`. Isolated key spaces (memory map or Redis prefix) SHALL stay as they are.

#### Scenario: Cache tests treat values as opaque
- **WHEN** a cache test Sets and Gets a payload
- **THEN** it uses a string literal, not a decisionscope or captcha const

### Requirement: Optional redisCacheInstanceId configures bouncer instance identity
When Redis cache is enabled, configuration SHALL expose optional string `redisCacheInstanceId`. The value SHALL be trimmed of outer ASCII space before use. When non-empty after trim, it SHALL be at most 128 Unicode runes and SHALL match `[A-Za-z0-9._-]+`. When empty after trim, effective instance identity SHALL come from the process hostname. When hostname resolution fails, effective identity SHALL be the literal `unknown-instance` and the plugin SHALL log one Warn with the error. Redis cache enablement SHALL remain controlled only by existing `redisCacheEnabled` and related Redis host fields; this knob MUST NOT add a second Redis enable flag.

#### Scenario: Operator sets pod name
- **WHEN** `redisCacheEnabled` is true and `redisCacheInstanceId` is `my-pod-7`
- **THEN** Redis cache keys for that bouncer use a prefix that includes `my-pod-7` after the existing LAPI identity hex base

#### Scenario: Empty knob uses hostname
- **WHEN** `redisCacheInstanceId` is omitted or blank after trim
- **THEN** the effective instance identity is the process hostname when available

#### Scenario: Invalid instance id rejected at config time
- **WHEN** `redisCacheInstanceId` contains characters outside `[A-Za-z0-9._-]+` after trim
- **THEN** configuration validation fails before the plugin serves traffic

### Requirement: LAPI stream cursor and Redis cache roles stay distinct
CrowdSec LAPI stream progress SHALL remain keyed by the bouncer database row (hashed API key plus LAPI-visible client IP). Redis used by this plugin SHALL be durable off-heap storage for remediations and the stream poll lease for one bouncer **instance** consuming that row. Redis MUST NOT act as a cross-replica stream bus or shared LAPI cursor between pods.

#### Scenario: Two pods with different outbound IPs
- **WHEN** two Traefik pods share one Redis and the same LAPI URL and API key but LAPI sees different client IPs
- **THEN** each pod MAY hold its own stream lease key in Redis without preventing the other from polling LAPI on its own cadence
