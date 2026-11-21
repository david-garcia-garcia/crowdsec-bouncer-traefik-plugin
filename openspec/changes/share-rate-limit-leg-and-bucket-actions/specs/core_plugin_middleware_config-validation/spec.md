## MODIFIED Requirements

### Requirement: Instance open versus subscribe validation
`ValidateParams` SHALL enforce the open-vs-subscribe matrix for each leg (LAPI, AppSec, captcha, ModSec, and the rate limit). When `bouncerEnabled` is false and the leg enable flag is false, a non-empty instance name, API key, or client certificate for that leg SHALL fail validation (E2). Captcha E2 is a leftover `captchaInstanceName` (not leftover owner-read `captcha*` keys). ModSec E2 is a leftover `modsecInstanceName` (not leftover owner-read `modsec*` keys). Rate-limit E2 is a leftover `rateLimitInstanceName` (not leftover owner-read `rateLimit*` keys, which a subscriber ignores). When `bouncerEnabled` is true, the leg enable flag is false, and the instance name is omitted after prepopulation rules, the bouncer SHALL NOT subscribe and validation SHALL succeed without treating the leg as open (E3). When a LAPI or AppSec enable flag is true and neither API key nor client certificate can build that client, `ValidateParams` or subsequent `Open` failure SHALL fail `New` for that middleware. When `captchaEnabled` is true, owner-style captcha checks SHALL fail `New` if provider, keys, or gate secret cannot build the client. When `modsecEnabled` is true, owner-style ModSec checks SHALL fail `New` if `modsecUrl` or `modsecBodyLimit` cannot build the client. When `rateLimitEnabled` is true, the owner-style rate-limit checks of requirement "Rate-limit settings are validated only on the owner" SHALL fail `New`. An empty or unloadable captcha template MUST NOT fail `New`.

#### Scenario: Leftover instance name with nothing enabled fails
- **WHEN** `bouncerEnabled` is false, `lapiEnabled` is false, and `lapiInstanceName` is `shared`
- **THEN** `ValidateParams` returns an error

#### Scenario: Bouncer with LAPI leg off and no name succeeds
- **WHEN** `bouncerEnabled` is true, `lapiEnabled` is false, AppSec is disabled, and `lapiInstanceName` is omitted
- **THEN** `ValidateParams` returns no error

#### Scenario: Leftover captcha instance name with nothing enabled fails
- **WHEN** `bouncerEnabled` is false, `captchaEnabled` is false, and `captchaInstanceName` is `shared`
- **THEN** `ValidateParams` returns an error

#### Scenario: Leftover ModSec instance name with nothing enabled fails
- **WHEN** `bouncerEnabled` is false, `modsecEnabled` is false, and `modsecInstanceName` is `shared`
- **THEN** `ValidateParams` returns an error

#### Scenario: Leftover rate-limit instance name with nothing enabled fails
- **WHEN** `bouncerEnabled` is false, `rateLimitEnabled` is false, and `rateLimitInstanceName` is `shared`
- **THEN** `ValidateParams` returns an error

#### Scenario: Rate-limit subscriber ignores leftover owner-read keys
- **WHEN** `bouncerEnabled` is true, `rateLimitEnabled` is false, `rateLimitInstanceName` is `shared`, and `rateLimitBuckets` has a row with `window: 500ms`
- **THEN** `ValidateParams` returns no error

## REMOVED Requirements

### Requirement: Rate-limit settings are validated only when the leg is enabled
**Reason**: The rate-limit policy now lives on the owner and the captcha on the subscriber, so the captcha check of `rateLimitFailureAction` moves out of startup validation, and bucket `action` values change (`deny` renamed `ratelimit`, `captcha` added). Replaced by "Rate-limit settings are validated only on the owner".
**Migration**: Rename `action: deny` to `action: ratelimit` (or omit it). Nothing else changes for a configuration that validated before.

## ADDED Requirements

### Requirement: Rate-limit settings are validated only on the owner
`rateLimitEnabled` SHALL default to false. Only a router with `rateLimitEnabled` true (the owner) SHALL have its `rateLimit*` settings validated, failing with an error that names the setting when a value is invalid; on any other router a leftover invalid bucket, duration, status, or password file SHALL NOT fail startup. `rateLimitFailureAction: captcha` SHALL pass whether or not the owner has a captcha instance name.

When `rateLimitEnabled` is true, `ValidateParams` SHALL fail, with an error that names the setting, when:

- `rateLimitStore` is not `redis` (default `redis`).
- `rateLimitRedisHost` is empty after trim (default `redis:6379`).
- `rateLimitRedisPasswordFile` is set and cannot be read (file-then-field lookup, as for `lapiRedisPasswordFile`). An empty password with no file SHALL pass.
- `rateLimitSyncRate` is not a Go duration or is negative (default `200ms`; `0` is valid).
- `rateLimitFailureAction` is not `passthrough`, `ban`, or `captcha` (default `passthrough`), with the same stems as `bouncerLapiFailureAction`.
- `rateLimitStatusCode` is below 100 or 600 and above (default 429).
- `rateLimitBuckets` is empty.
- a bucket row fails. Inner errors SHALL be index-prefixed `bucket %d: …` and wrapped `RateLimitBuckets: %w`. A row SHALL fail when: `name` is empty after trim, contains `:`, or repeats another row's name; a `method`, `path`, `host`, `headers`, or `cookies` pattern is not valid Go RE2, or `method` is `!!` or a bare `!`; `requests` is below 1; `window` is not a Go duration, is below 1s, or is not a whole number of seconds; `action` is set and is not `ratelimit`, `captcha`, or `log`; `algorithm` is set and is not `slidingWindow`; `burst` is set; a key part has an unknown `from`; `name` is missing on a `header`, `cookie`, or `query` part or set on any other part; `ipv4Prefix` is outside 1–32 or `ipv6Prefix` outside 1–128, or either is set on a part that is not `from: ip`; `pattern` is not valid Go RE2 or has no capture group.

A row with no predicate SHALL pass (it matches every request). `ValidateParams` SHALL compile and discard the bucket list; the owner's `New` SHALL compile it again into the rate-limit client. A `ValidateParams` failure SHALL cause `plugin.New` to return a nil handler and that error without opening any leg.

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

#### Scenario: Captcha failure action on an owner without a captcha passes
- **WHEN** `rateLimitEnabled` is true, `rateLimitFailureAction` is `captcha`, and the owner has no captcha instance name
- **THEN** `ValidateParams` returns no error from that setting

#### Scenario: Captcha bucket on an owner without a captcha passes
- **WHEN** `rateLimitEnabled` is true, a bucket sets `action: captcha`, and the owner has no captcha instance name
- **THEN** `ValidateParams` returns no error from that bucket

#### Scenario: Deny action fails
- **WHEN** a bucket sets `action: deny`
- **THEN** `ValidateParams` fails with an error that names `RateLimitBuckets` and `bucket 0`

#### Scenario: Missing password file fails when enabled
- **WHEN** `rateLimitEnabled` is true and `rateLimitRedisPasswordFile` points at a missing file
- **THEN** `ValidateParams` fails
- **AND** `New` returns a nil handler and that error
