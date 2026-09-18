## MODIFIED Requirements

### Requirement: Cache payloads stay opaque strings
A cache Client SHALL store and return opaque strings for Redis payloads, the stream lease key, and the `range-index` blob document. The cache package MUST NOT export CrowdSec remediation names (`BannedValue`, `CaptchaValue`, `NoBannedValue`). Store errors SHALL remain `CacheMiss` and `CacheUnreachable`. On the stream/alone memory backend, Ip and header-scope remediation slots MAY store a packed kind-plus-origin-id word instead of a string; packed-value ownership lives on `core_cache_client_origin-dictionary`. Cache tests that are not those memory remediation slots SHALL keep using string literals.

#### Scenario: Cache tests treat values as opaque
- **WHEN** a cache test Sets and Gets a non-remediation payload
- **THEN** it uses a string literal, not a decisionscope or captcha const

#### Scenario: Memory remediation slot may be packed
- **WHEN** stream/alone memory stores an interned Ip ban
- **THEN** that slot's ttl_map value MAY be a packed word rather than a string
- **AND** Redis Get of a remediating IP still returns a string
