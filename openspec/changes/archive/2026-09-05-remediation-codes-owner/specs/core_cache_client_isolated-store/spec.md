## ADDED Requirements

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
