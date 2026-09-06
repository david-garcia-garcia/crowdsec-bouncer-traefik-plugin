## Purpose

Each Crowdsec connection’s cache Client has an isolated key space so two **sessions** in one process cannot read or write each other’s remediations, captcha grace, or stream lease. Stream/alone middlewares that share a LAPI session share one Client (one prefix).

## Requirements

### Requirement: Memory cache is per Client not process-wide
When redis is disabled, a cache Client SHALL store keys in a map owned by that Client. The package MUST NOT keep a process-wide TTL map shared by all Clients.

#### Scenario: Two memory clients do not leak
- **WHEN** Client A sets key `1.2.3.4` to banned
- **AND** Client B is a different Client in the same process
- **THEN** Client B’s get of `1.2.3.4` is a miss

### Requirement: Redis keys are prefixed with session identity for stream
When redis is enabled, every GET/SET/DEL key the cache sends SHALL be prefixed. For stream/alone the prefix SHALL be the stream session hex (LAPI URL+key), not leftover extras (intervals, Redis host is the Client’s target, not the prefix). For live/none the prefix SHALL remain the full connection identity. Two Clients that share a Redis host and different prefixes MUST NOT observe each other’s decisions, captcha grace keys, or the stream lease key.

#### Scenario: Same Redis host two prefixes
- **WHEN** two Clients share one Redis-protocol host and different prefixes
- **AND** the first sets a banned IP
- **THEN** the second’s get of that IP is a miss

### Requirement: Stream lease is per stream session
The stream poller lease key SHALL live in that connection’s isolated cache space. Two stream **sessions** (different LAPI URL or key) MUST NOT skip a poll because the other wrote the lease. Two stream middlewares on the **same** session share one lease and one poller.

#### Scenario: Two stream sessions both poll
- **WHEN** two stream-mode connections exist in one process for different LAPI hosts
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
