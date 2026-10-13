## MODIFIED Requirements

### Requirement: Cache payloads stay opaque strings
A cache Client SHALL store and return opaque strings. The cache package MUST NOT export CrowdSec remediation names (`BannedValue`, `CaptchaValue`, `NoBannedValue`). Store errors SHALL be the package sentinels `ErrMiss` and `ErrUnreachable`. Their `Error()` text SHALL remain `CacheMiss` (`cache:miss`) and `CacheUnreachable` (`cache:unreachable`). Callers that distinguish miss from unreachable SHALL use `errors.Is`. A clean miss MUST NOT allocate a new error value. Memory and Redis backends SHALL return the same sentinels. GetMany SHALL keep omitting missing keys.

#### Scenario: Cache tests treat values as opaque
- **WHEN** a cache test Sets and Gets a payload
- **THEN** it uses a string literal, not a decisionscope or captcha const

#### Scenario: In-memory miss is the miss sentinel
- **WHEN** a memory DecisionStore Get of an absent key returns an error
- **THEN** `errors.Is(err, ErrMiss)` is true
- **AND** `err.Error()` is `cache:miss`

#### Scenario: Redis unreachable is the unreachable sentinel
- **WHEN** a Redis DecisionStore Get fails because the store is unreachable
- **THEN** `errors.Is(err, ErrUnreachable)` is true
- **AND** `err.Error()` is `cache:unreachable`

#### Scenario: Lookup miss is the miss sentinel
- **WHEN** `LookupCachedRemediation` finds no active remediation and the Ip key is absent
- **THEN** the returned error satisfies `errors.Is(err, ErrMiss)`
