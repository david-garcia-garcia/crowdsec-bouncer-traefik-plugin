## ADDED Requirements

### Requirement: Rate-limit settings are validated only when the leg is enabled
`rateLimitEnabled` SHALL default to false. When it is false, `ValidateParams` SHALL NOT read any other `rateLimit*` setting: a leftover invalid bucket, duration, status, or password file SHALL NOT fail startup.

When `rateLimitEnabled` is true, `ValidateParams` SHALL fail, with an error that names the setting, when:

- `rateLimitStore` is not `redis` (default `redis`).
- `rateLimitRedisHost` is empty after trim (default `redis:6379`).
- `rateLimitRedisPasswordFile` is set and cannot be read (file-then-field lookup, as for `lapiRedisPasswordFile`). An empty password with no file SHALL pass.
- `rateLimitSyncRate` is not a Go duration or is negative (default `200ms`; `0` is valid).
- `rateLimitFailureAction` is not `passthrough`, `ban`, or `captcha` (default `passthrough`), or is `captcha` on a router without a captcha instance name after owner-fill, with the same stems as `bouncerLapiFailureAction`.
- `rateLimitStatusCode` is below 100 or 600 and above (default 429).
- `rateLimitBuckets` is empty.
- a bucket row fails. Inner errors SHALL be index-prefixed `bucket %d: …` and wrapped `RateLimitBuckets: %w`. A row SHALL fail when: `name` is empty after trim, contains `:`, or repeats another row's name; a `method`, `path`, `host`, `headers`, or `cookies` pattern is not valid Go RE2, or `method` is `!!` or a bare `!`; `requests` is below 1; `window` is not a Go duration, is below 1s, or is not a whole number of seconds; `action` is set and is not `deny` or `log`; `algorithm` is set and is not `slidingWindow`; `burst` is set; a key part has an unknown `from`; `name` is missing on a `header`, `cookie`, or `query` part or set on any other part; `ipv4Prefix` is outside 1–32 or `ipv6Prefix` outside 1–128, or either is set on a part that is not `from: ip`; `pattern` is not valid Go RE2 or has no capture group.

A row with no predicate SHALL pass (it matches every request). `ValidateParams` SHALL compile and discard the bucket list; the Bouncer SHALL compile it again to store it. A `ValidateParams` failure SHALL cause `plugin.New` to return a nil handler and that error without opening any leg.

#### Scenario: Disabled leg ignores leftover invalid settings
- **WHEN** `rateLimitEnabled` is false
- **AND** `rateLimitBuckets` has a row with `window: 500ms` and `rateLimitRedisPasswordFile` points at a missing file
- **THEN** `ValidateParams` returns no error from those settings

#### Scenario: Enabled leg with no bucket fails
- **WHEN** `rateLimitEnabled` is true and `rateLimitBuckets` is empty
- **THEN** `ValidateParams` fails with an error that names `RateLimitBuckets`

#### Scenario: Fractional window fails
- **WHEN** a bucket has `window: 1500ms`
- **THEN** `ValidateParams` fails with an error that names `RateLimitBuckets` and `bucket 0`

#### Scenario: Catch-all bucket passes
- **WHEN** a bucket has `name`, `requests: 300`, `window: 1m`, a `key` of `from: ip`, and no predicate
- **THEN** `ValidateParams` returns no error from that bucket

#### Scenario: Pattern without a capture group fails
- **WHEN** a key part is `{from: path, pattern: "^/t/[^/]+/"}`
- **THEN** `ValidateParams` fails with an error that names `RateLimitBuckets`

#### Scenario: Captcha failure action without a captcha instance fails
- **WHEN** `rateLimitFailureAction` is `captcha` and the router has no captcha instance name after owner-fill
- **THEN** `ValidateParams` fails with an error that names `RateLimitFailureAction` and `captcha requires a captcha instance name`

#### Scenario: Missing password file fails when enabled
- **WHEN** `rateLimitEnabled` is true and `rateLimitRedisPasswordFile` points at a missing file
- **THEN** `ValidateParams` fails
- **AND** `New` returns a nil handler and that error
