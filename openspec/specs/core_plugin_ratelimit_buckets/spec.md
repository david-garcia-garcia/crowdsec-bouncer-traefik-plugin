## Purpose

A bucket is one named rate limit on `rateLimitBuckets`: which requests it counts, what its counter is per, how many requests it allows in a window, and what happens over the limit. This capability owns the bucket row, the order buckets are charged in, and the response a denying bucket writes.

## Requirements

### Requirement: A bucket row selects requests with action-rule predicates
Each row of `rateLimitBuckets` SHALL have a `name` and MAY carry the request predicates of a `bouncerActionRules` row, flat on the row: `method`, `path`, `host`, `headers`, `cookies`. They SHALL match exactly as they match on an action rule (Go RE2, unanchored, set predicates AND, empty header or cookie pattern = present, `!` negation on `method` only, path is `req.URL.Path`, host is the hostname of `req.Host`). A row with no predicate set SHALL match every request. A `path` predicate on a bucket SHALL be applied as written; it has no single-reading path check.

#### Scenario: Catch-all bucket
- **WHEN** a bucket has no `method`, `path`, `host`, `headers`, or `cookies`
- **THEN** it matches every request that reaches the rate-limit step

#### Scenario: Method and path both required
- **WHEN** a bucket has `method: ^POST$` and `path: ^/login$`
- **THEN** `POST /login` matches
- **AND** `GET /login` does not match

#### Scenario: Header presence
- **WHEN** a bucket has `headers: {Authorization: ""}`
- **THEN** a request with any `Authorization` value matches
- **AND** a request without `Authorization` does not match

### Requirement: A bucket key says what the counter is per
`key` SHALL be a list of parts. Each part SHALL have `from`, one of `ip`, `header`, `cookie`, `query`, `host`, `path`, `method`:

- `ip`: the client address this plugin already resolved for the request (the address `bouncerForwardedHeaders*` and `bouncerClientTrustedIps` see). `ipv4Prefix` (1–32) and `ipv6Prefix` (1–128) SHALL mask the address to that network before it is used; omitted means the full address. An IPv4-mapped IPv6 address SHALL count as IPv4.
- `header`, `cookie`, `query`: the first value of the request header, cookie, or URL query parameter named by `name`. Header names SHALL be case-insensitive; cookie and query names SHALL be case-sensitive.
- `host`: the hostname of `req.Host`, as the `host` predicate reads it.
- `path`: `req.URL.Path`.
- `method`: `req.Method`.

A part MAY have `pattern`, a Go RE2 with at least one capture group. When set, the part's value SHALL be capture group 1 of the first match, and no match SHALL mean the value is missing.

The parts SHALL be joined in list order to form the counter key. An empty `key` list SHALL mean one counter for every request the bucket matches. A missing value in any part (absent header, cookie, or query parameter, an empty value, or a `pattern` that does not match) SHALL skip the bucket for that request: it is not charged, cannot deny, and its `final` does not apply.

#### Scenario: Per client address
- **WHEN** a bucket keys on `from: ip` and allows 5 requests per minute
- **AND** clients `198.51.100.1` and `198.51.100.2` each send 5 requests within the minute
- **THEN** none of those 10 requests is denied

#### Scenario: IPv6 prefix groups a network
- **WHEN** a bucket keys on `from: ip` with `ipv6Prefix: 64` and allows 5 requests per minute
- **AND** clients `2001:db8::1` and `2001:db8::2` send 3 requests each within the minute
- **THEN** at least one of those 6 requests is denied

#### Scenario: Capture group selects the tenant
- **WHEN** a bucket keys on `from: path` with `pattern: ^/t/([^/]+)/`
- **THEN** `/t/acme/orders` and `/t/acme/users` count against one counter
- **AND** `/t/other/orders` counts against another

#### Scenario: Missing header skips the bucket
- **WHEN** a bucket keys on `from: header` with `name: Authorization`
- **AND** the request has no `Authorization` header
- **THEN** the bucket is not charged and does not deny that request

### Requirement: Matching buckets are charged in list order
For a request that reaches the rate-limit step, the plugin SHALL walk `rateLimitBuckets` in list order. For each bucket that matches and has a key value, it SHALL count one hit against that bucket's counter, then compare the sliding-window estimate with `requests` per `window`. A hit SHALL be counted even when it is over the limit.

- A `deny` bucket over its limit SHALL answer the request (requirement "A deny bucket answers with the rate-limit status and Retry-After"). Later buckets SHALL NOT be charged.
- A `log` bucket over its limit SHALL log at INFO `crowdsec bouncer rate limit exceeded` with attributes `ip`, `bucket`, `requests`, and `window`, and evaluation SHALL continue.
- A matching bucket with `final: true` SHALL stop the walk after that bucket, whether or not it was over its limit.
- When no bucket denies, the request SHALL continue to the AppSec step.

`action` SHALL default to `deny`. `final` SHALL default to false. `algorithm` SHALL default to `slidingWindow`.

#### Scenario: First deny bucket answers and later buckets are not charged
- **WHEN** buckets `login` (deny, 1 per minute) and `per-ip` (deny, 100 per minute) both match `POST /login`
- **AND** one client sends 2 requests
- **THEN** the second request is denied by `login`
- **AND** `per-ip` counts only the first request

#### Scenario: Log bucket never stops the request
- **WHEN** a `log` bucket allows 1 request per minute
- **AND** one client sends 3 requests
- **THEN** all 3 requests reach the backend
- **AND** the INFO line is logged for the second and third request

#### Scenario: Final stops evaluation
- **WHEN** bucket `static` has `final: true` and matches `GET /app.js`
- **AND** a later catch-all bucket allows 1 request per minute
- **THEN** repeated `GET /app.js` requests are never denied by the catch-all bucket

#### Scenario: A denied client stays limited while it keeps sending
- **WHEN** a bucket allows 5 requests per minute and one client sends 1 request per second for 2 minutes
- **THEN** that client is denied for most of the second minute too, because denied hits are counted

### Requirement: A deny bucket answers with the rate-limit status and Retry-After
A denying bucket SHALL answer with the router's ban page and status `rateLimitStatusCode` (default 429). The body rules SHALL be those of the ban page: no body for `HEAD`, 204, or 304, and an empty body when no ban template is loaded. `Cache-Control: no-cache, no-store` SHALL be set. The ban template SHALL receive `RemediationReason` `RATE_LIMIT`. `bouncerRemediationStatusCode` SHALL NOT change this status.

When `rateLimitResponseHeaders` is true (default), the response SHALL carry `Retry-After` with the whole number of seconds until the bucket's current window ends, at least 1. When false, no `Retry-After` is sent. `RateLimit-*` headers SHALL NOT be sent.

The remediation header, when configured, SHALL be `ban:ratelimit:<bucket name>`. A deny SHALL count one usage-metrics drop with origin `plugin:ratelimit:<bucket name>` and remediation `ban` (`core_plugin_lapi_usage-metrics`).

#### Scenario: Deny answers 429 with Retry-After
- **WHEN** a `deny` bucket `login` with `window: 60s` is over its limit at second 45 of its window
- **THEN** the status is 429
- **AND** `Retry-After` is `15`
- **AND** the remediation header is `ban:ratelimit:login` when `bouncerRemediationHeadersCustomName` is set

#### Scenario: Status code setting is separate from the ban status
- **WHEN** `bouncerRemediationStatusCode` is 403 and `rateLimitStatusCode` is 503
- **THEN** a rate-limit deny answers 503
- **AND** a LAPI ban still answers 403

#### Scenario: Response headers off
- **WHEN** `rateLimitResponseHeaders` is false and a bucket denies
- **THEN** the response has no `Retry-After`

### Requirement: Bucket values not in this version fail validation
`algorithm` SHALL accept only `slidingWindow`. `action` SHALL accept only `deny` and `log`. A row that sets `algorithm: tokenBucket`, `burst`, or `action: captcha` SHALL fail `ValidateParams` with an error that names the row and says the value is not supported in this version. `rateLimitStore` SHALL accept only `redis`; `memory` SHALL fail the same way.

#### Scenario: Token bucket is rejected
- **WHEN** a bucket sets `algorithm: tokenBucket`
- **THEN** `ValidateParams` fails with an error that names `RateLimitBuckets` and `tokenBucket`

#### Scenario: Captcha action is rejected
- **WHEN** a bucket sets `action: captcha`
- **THEN** `ValidateParams` fails with an error that names `RateLimitBuckets` and `captcha`

#### Scenario: Memory store is rejected
- **WHEN** `rateLimitStore` is `memory` and `rateLimitEnabled` is true
- **THEN** `ValidateParams` fails with an error that names `RateLimitStore`
