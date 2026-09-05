## Purpose

Each Crowdsec connection’s cache Client has an isolated key space so two configs in one process cannot read or write each other’s remediations, captcha grace, or stream lease.

## Requirements

### Requirement: Memory cache is per Client not process-wide
When redis is disabled, a cache Client SHALL store keys in a map owned by that Client. The package MUST NOT keep a process-wide TTL map shared by all Clients.

#### Scenario: Two memory clients do not leak
- **WHEN** Client A sets key `1.2.3.4` to banned
- **AND** Client B is a different Client in the same process
- **THEN** Client B’s get of `1.2.3.4` is a miss

### Requirement: Redis keys are prefixed with connection identity
When redis is enabled, every GET/SET/DEL key the cache sends SHALL be prefixed with the connection identity used as the reclaim key (or an equivalent unique prefix for that Client). Two Clients that share a Redis host MUST NOT observe each other’s decisions, captcha grace keys, or the stream lease key.

#### Scenario: Same Redis host two prefixes
- **WHEN** two Clients share one Redis-protocol host and different connection identities
- **AND** the first sets a banned IP
- **THEN** the second’s get of that IP is a miss

### Requirement: Stream lease is per connection
The stream poller lease key SHALL live in that connection’s isolated cache space. Two stream connections MUST NOT skip a poll because the other wrote the lease.

#### Scenario: Two stream connections both poll
- **WHEN** two stream-mode connections exist in one process
- **THEN** each performs its own stream fetch against its own LAPI
- **AND** neither treats the other’s lease as its own

### Requirement: Cache payloads are opaque strings
A cache Client SHALL store and return opaque strings. The cache package MUST NOT export CrowdSec remediation names (`BannedValue`, `CaptchaValue`, `NoBannedValue`, `CaptchaDoneValue`). Store errors SHALL remain `CacheMiss` and `CacheUnreachable`. Isolated key spaces (memory map or Redis prefix) SHALL stay as they are.

#### Scenario: Cache tests treat values as opaque
- **WHEN** a cache test Sets and Gets a payload
- **THEN** it uses a string literal, not a decisionscope or captcha const

### Requirement: Captcha grace-done payload is owned by captcha
The captcha grace key (`{ip}_captcha`) SHALL store `CaptchaDoneValue` (`d`) declared on `pkg/captcha`. Wire value MUST remain `d` so existing Redis and memory grace entries stay valid.

#### Scenario: Solved captcha still stores d
- **WHEN** a captcha challenge is solved
- **THEN** `{ip}_captcha` is Set to `d`
