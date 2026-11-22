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
For a request that reaches the rate-limit step, the plugin SHALL walk the buckets of the rate-limit client the router is bound to, in list order. For each bucket that matches and has a key value, it SHALL count one hit against that bucket's counter with the owner's `rateLimitAlgorithm` (requirement "The owner chooses the counting algorithm of every bucket"), then decide whether that hit is over the limit. With `slidingWindow` a hit SHALL be counted even when it is over the limit. With `tokenBucket` a hit over the limit SHALL NOT consume a token.

- A `ratelimit` bucket over its limit SHALL answer the request (requirement "A ratelimit bucket answers with the rate-limit status and Retry-After"). Later buckets SHALL NOT be charged.
- A `captcha` bucket over its limit SHALL NOT stop the walk. The first such bucket in list order SHALL be kept, and when the walk ends without a `ratelimit` answer it SHALL answer the request (requirement "A captcha bucket answers with the router's captcha").
- A `log` bucket over its limit SHALL log at INFO `crowdsec bouncer rate limit exceeded` with attributes `ip`, `bucket`, `requests`, and `window`, and evaluation SHALL continue.
- A matching bucket with `final: true` SHALL stop the walk after that bucket, whether or not it was over its limit.
- When the router has a usable captcha client and the request carries a valid captcha gate cookie, every `captcha` bucket SHALL be skipped: it is not charged, cannot answer, and its `final` does not apply. `ratelimit` and `log` buckets SHALL still be charged.
- The answer SHALL follow the precedence `ratelimit` over `captcha` over `log`.
- When no bucket answers, the request SHALL continue to the AppSec step.

`action` SHALL default to `ratelimit`. `final` SHALL default to false. `burst` SHALL default to `requests` and SHALL be read only with `tokenBucket`.

#### Scenario: First deny bucket answers and later buckets are not charged
- **WHEN** buckets `login` (`ratelimit`, 1 per minute) and `per-ip` (`ratelimit`, 100 per minute) both match `POST /login`
- **AND** one client sends 2 requests
- **THEN** the second request is answered by `login`
- **AND** `per-ip` counts only the first request

#### Scenario: Log bucket never stops the request
- **WHEN** a `log` bucket allows 1 request per minute
- **AND** one client sends 3 requests
- **THEN** all 3 requests reach the backend
- **AND** the INFO line is logged for the second and third request

#### Scenario: Final stops evaluation
- **WHEN** bucket `static` has `final: true` and matches `GET /app.js`
- **AND** a later catch-all bucket allows 1 request per minute
- **THEN** repeated `GET /app.js` requests are never answered by the catch-all bucket

#### Scenario: A denied client stays limited while it keeps sending
- **WHEN** `rateLimitAlgorithm` is `slidingWindow`, a `ratelimit` bucket allows 5 requests per minute, and one client sends 1 request per second for 2 minutes
- **THEN** that client is answered by the bucket for most of the second minute too, because answered hits are counted

#### Scenario: A token bucket admits at the refill rate after a deny
- **WHEN** `rateLimitAlgorithm` is `tokenBucket`, a `ratelimit` bucket allows 6 requests per minute with `burst` 2, and one client sends 1 request per second for 1 minute
- **THEN** the first 2 requests reach the backend
- **AND** after that about one request every 10 seconds reaches the backend and the others are answered by the bucket, because answered hits do not consume a token

#### Scenario: A stacked ratelimit bucket is the hard ceiling
- **WHEN** bucket `per-ip-soft` (`captcha`, 2 per minute) and bucket `per-ip-hard` (`ratelimit`, 4 per minute) both key on `from: ip`
- **AND** a client that never solves the captcha sends 5 requests within the minute
- **THEN** requests 1 and 2 reach the backend
- **AND** requests 3 and 4 get the captcha challenge for `per-ip-soft`
- **AND** request 5 is answered by `per-ip-hard`

#### Scenario: A solved client is not counted by captcha buckets
- **WHEN** the same two buckets apply and the client holds a valid captcha gate cookie of this router
- **AND** it sends 5 requests within the minute
- **THEN** requests 1 to 4 reach the backend
- **AND** request 5 is answered by `per-ip-hard`
- **AND** the counter of `per-ip-soft` does not move

#### Scenario: A counter error wins over a kept captcha bucket
- **WHEN** a `captcha` bucket is over its limit and a later bucket's counter returns an error
- **THEN** the rate-limit failure action answers the request, not the captcha bucket

### Requirement: A ratelimit bucket answers with the rate-limit status and Retry-After
A `ratelimit` bucket that answers SHALL write the subscribing router's ban page with the owner's `rateLimitStatusCode` (default 429). The body rules SHALL be those of the ban page: no body for `HEAD`, 204, or 304, and an empty body when no ban template is loaded. `Cache-Control: no-cache, no-store` SHALL be set. The ban template SHALL receive `RemediationReason` `RATE_LIMIT`. `bouncerRemediationStatusCode` SHALL NOT change this status.

When the owner's `rateLimitResponseHeaders` is true (default), the response SHALL carry `Retry-After` with the counter's `RetryAfter` for that hit: with `slidingWindow` (`windowcounter.Status`, utilities v1.0.10+) the time until the first whole second at which one more hit on the same key is admitted with no other traffic, sliding-window weight included; with `tokenBucket` (`tokenbucket.Status`) the time until the bucket holds one token again. It SHALL be rounded up to whole seconds, at least 1. When false, no `Retry-After` is sent. `RateLimit-*` headers SHALL NOT be sent.

The remediation header, when configured, SHALL be `ban:ratelimit:<bucket name>`. The answer SHALL count one usage-metrics drop with origin `plugin:ratelimit:<bucket name>` and remediation `ban` (`core_plugin_lapi_usage-metrics`).

A `captcha` bucket that answers as `ratelimit` (requirement "A captcha bucket answers with the router's captcha") SHALL write this same response for that bucket.

#### Scenario: Deny answers 429 with Retry-After
- **WHEN** a `ratelimit` bucket `login` with `requests: 3` and `window: 60s` answers a client's fourth hit at second 45 of its window, with no hits in the previous window
- **THEN** the status is 429
- **AND** `Retry-After` is `45`: 15s to the window end, then 30s until 1 + 4 x (1 - t/60) fits in 3
- **AND** the remediation header is `ban:ratelimit:login` when `bouncerRemediationHeadersCustomName` is set

#### Scenario: Status code setting is separate from the ban status
- **WHEN** `bouncerRemediationStatusCode` is 403 and the owner's `rateLimitStatusCode` is 503
- **THEN** a `ratelimit` bucket answers 503
- **AND** a LAPI ban still answers 403

#### Scenario: Token bucket Retry-After is the refill time
- **WHEN** `rateLimitAlgorithm` is `tokenBucket` and a `ratelimit` bucket with `requests: 1`, `window: 10s`, and `burst: 2` answers a client's third request sent at once
- **THEN** the status is 429
- **AND** `Retry-After` is `10`

#### Scenario: Response headers off
- **WHEN** the owner's `rateLimitResponseHeaders` is false and a `ratelimit` bucket answers
- **THEN** the response has no `Retry-After`

### Requirement: Bucket algorithm, action, and store values are validated
A row that sets `algorithm`, whatever its value, SHALL fail `ValidateParams` with an error that names the row and `rateLimitAlgorithm`: the algorithm is chosen for the whole limiter. `action` SHALL accept only `ratelimit`, `captcha`, and `log`. A row whose `action` is any other value, `deny` included, SHALL fail with an error that names the row and the accepted values. `rateLimitStore` SHALL accept only `redis`; `memory` SHALL fail as not supported in this version.

#### Scenario: A bucket algorithm points at the limiter setting
- **WHEN** a bucket sets `algorithm: tokenBucket`
- **THEN** `ValidateParams` fails with an error that names `RateLimitBuckets`, `bucket 0`, and `rateLimitAlgorithm`

#### Scenario: Deny action is rejected
- **WHEN** a bucket sets `action: deny`
- **THEN** `ValidateParams` fails with an error that names `RateLimitBuckets` and lists `ratelimit`, `captcha`, and `log`

#### Scenario: Captcha action is accepted
- **WHEN** a bucket sets `action: captcha`
- **THEN** `ValidateParams` returns no error from that bucket

#### Scenario: Memory store is rejected
- **WHEN** `rateLimitStore` is `memory` and `rateLimitEnabled` is true
- **THEN** `ValidateParams` fails with an error that names `RateLimitStore`

### Requirement: A captcha bucket answers with the router's captcha
A `captcha` bucket that answers SHALL serve the subscribing router's captcha challenge page with remediation header `captcha:ratelimit:<bucket name>`. A solve SHALL set the router's captcha gate, valid for `captchaGracePeriodSeconds`. It SHALL answer as a `ratelimit` bucket instead when a `bypassCaptcha` action rule matches the request, or when the router has no usable captcha client (not subscribed, not published, or not valid).

#### Scenario: Over-limit captcha bucket serves the challenge
- **WHEN** `captcha` bucket `per-ip-soft` is over its limit for a client without a valid gate on a router subscribed to a published captcha
- **THEN** the response is that router's captcha challenge page
- **AND** the remediation header is `captcha:ratelimit:per-ip-soft` when `bouncerRemediationHeadersCustomName` is set

#### Scenario: bypassCaptcha turns the captcha bucket into a rate limit
- **WHEN** `captcha` bucket `per-ip-soft` is over its limit and a `bypassCaptcha` action rule matches the request
- **THEN** the response is the `ratelimit` answer for `per-ip-soft`: `rateLimitStatusCode`, `Retry-After`, and `ban:ratelimit:per-ip-soft`
- **AND** the request does not reach the backend

#### Scenario: Router without a captcha answers as a rate limit
- **WHEN** `captcha` bucket `per-ip-soft` is over its limit and the subscribing router has no captcha instance name
- **THEN** the response is the `ratelimit` answer for `per-ip-soft`
- **AND** it is not `ban:captcha-downgrade`

#### Scenario: Solving the challenge lets the client through
- **WHEN** a client solves the challenge served for `per-ip-soft`
- **THEN** its next request within `captchaGracePeriodSeconds` is not counted by `per-ip-soft`

### Requirement: The captcha page's own requests are not charged
When the subscribing router has a usable captcha client, a request for one of that captcha's same-origin widget assets (custom provider) SHALL skip every bucket: none is charged, none answers, and the failure action does not apply. A request that carries the challenge-form marker `crowdsec_captcha_challenge=v1` SHALL skip every bucket in the same way only when the router's captcha gate answers it for the rate limit: the router has a usable captcha client, the bound policy can answer with a captcha (a `captcha` bucket, or `rateLimitFailureAction: captcha`), and no `bypassCaptcha` action rule matched. Every other marker request SHALL be charged like any other request. On a router without a usable captcha client widget-asset requests SHALL be charged like any other. The request that follows a solve SHALL be charged like any other. The policy and `bypassCaptcha` checks SHALL come before the request body is read for the marker, so a router whose policy has no captcha answer does not read POST bodies in this step.

A widget asset SHALL continue to the AppSec step. A challenge-form POST that skips the buckets SHALL be answered by the router's captcha gate: a valid answer gets the 302 solved redirect with header `captcha:solved` and the gate cookie; any other answer gets the challenge page again with header `captcha:ratelimit` (no third field: no bucket answered) and one `captcha` drop under origin `plugin:ratelimit`. This holds whether or not the router also subscribes to AppSec.

#### Scenario: Verification POST is not charged
- **WHEN** a client whose `captcha` and `ratelimit` buckets are both over their limits posts the challenge form with the marker
- **THEN** no bucket counter moves
- **AND** the request is not answered by a bucket

#### Scenario: Verification POST solves the challenge without AppSec
- **WHEN** a router with a usable captcha and no AppSec subscription served the challenge for `per-ip-soft`
- **AND** the client posts the challenge form with the marker and a valid answer
- **THEN** the response is 302 with header `captcha:solved` and the gate cookie
- **AND** the form does not reach the application and no bucket counter moves

#### Scenario: Verification POST with a wrong answer gets the challenge again
- **WHEN** the client posts the challenge form with the marker and an answer the provider rejects
- **THEN** the response is the challenge page with header `captcha:ratelimit`
- **AND** usage metrics count one `captcha` drop under origin `plugin:ratelimit`

#### Scenario: Marker POST on a policy without a captcha answer is charged
- **WHEN** the bound policy has only `ratelimit` and `log` buckets and failure action `passthrough`
- **AND** a client over a `ratelimit` bucket's limit posts a form with the marker on a router with a usable captcha and no AppSec subscription
- **THEN** every matching bucket is charged
- **AND** the response is the `ratelimit` answer with header `ban:ratelimit:<bucket>`, and the form does not reach the application

#### Scenario: Marker POST matching a bypassCaptcha rule is charged
- **WHEN** the bound policy has a `captcha` bucket and a `ratelimit` bucket, and a `bypassCaptcha` action rule matches the POST
- **AND** a client over the `ratelimit` bucket's limit posts a form with the marker on a router with a usable captcha
- **THEN** every matching bucket is charged
- **AND** the response is the `ratelimit` answer with header `ban:ratelimit:<bucket>`

#### Scenario: Marker POST no gate answers leaves its body unread
- **WHEN** the bound policy has no captcha answer, or a `bypassCaptcha` action rule matches
- **AND** a POST with the marker reaches the rate-limit step on a router with a usable captcha
- **THEN** the rate-limit step does not read the request body

#### Scenario: Widget asset is not charged
- **WHEN** the router's captcha uses the custom provider and a client fetches one of its widget asset paths
- **THEN** no bucket counter moves

#### Scenario: Marker on a router without a captcha is charged
- **WHEN** the subscribing router has no captcha instance name and a request carries the challenge-form marker
- **THEN** every matching bucket is charged

### Requirement: Rate-limit captcha downgrades log on transitions
This covers both captcha answers of the leg: a `captcha` bucket and failure action `captcha`. A client whose policy uses either, bound on a router without a captcha subscription, SHALL log one ERROR `crowdsec bouncer rate limit captcha unavailable`, `reason` `unsubscribed`. A downgrade on a router whose captcha is unpublished or invalid SHALL log it with `reason` `unusable` at most every 5 seconds. Each downgraded request SHALL log DEBUG only, never WARN `crowdsec bouncer captcha unsubscribed`.

#### Scenario: Bind on a router without a captcha logs once
- **WHEN** a router without a captcha instance name binds a rate-limit client that has a `captcha` bucket
- **AND** that bucket then answers 3 requests as `ratelimit`
- **THEN** ERROR `crowdsec bouncer rate limit captcha unavailable` with `reason` `unsubscribed` is logged once
- **AND** WARN `crowdsec bouncer captcha unsubscribed` is not logged

#### Scenario: Unpublished captcha logs at most every 5 seconds
- **WHEN** a router subscribes to a captcha that is not published
- **AND** a `captcha` bucket answers 10 requests as `ratelimit` within one second
- **THEN** ERROR `crowdsec bouncer rate limit captcha unavailable` with `reason` `unusable` is logged once in that second

#### Scenario: Policy without a captcha answer logs nothing
- **WHEN** a router without a captcha instance name binds a rate-limit client with only `ratelimit` and `log` buckets and failure action `passthrough`
- **THEN** no ERROR `crowdsec bouncer rate limit captcha unavailable` is logged

### Requirement: Burst and the limiter algorithm are validated
`rateLimitAlgorithm` SHALL accept only `slidingWindow` and `tokenBucket`. `burst` SHALL be at least 1 when set. A row that sets `burst` while `rateLimitAlgorithm` is `slidingWindow` SHALL fail `ValidateParams` with an error that names the row and `rateLimitAlgorithm`. With `tokenBucket`, a row whose full refill (`burst` × `window` / `requests`) exceeds 8760h SHALL fail.

#### Scenario: Burst with the sliding window is rejected
- **WHEN** `rateLimitAlgorithm` is `slidingWindow` and a bucket sets `burst: 10`
- **THEN** `ValidateParams` fails with an error that names `RateLimitBuckets` and `rateLimitAlgorithm`

#### Scenario: Burst with the token bucket is accepted
- **WHEN** `rateLimitAlgorithm` is `tokenBucket` and a bucket sets `requests: 60`, `window: 1m`, and `burst: 10`
- **THEN** `ValidateParams` returns no error from that bucket

#### Scenario: Unknown algorithm is rejected
- **WHEN** `rateLimitAlgorithm` is `leakyBucket`
- **THEN** `ValidateParams` fails with an error that names `RateLimitAlgorithm`

### Requirement: The owner chooses the counting algorithm of every bucket
The owner's `rateLimitAlgorithm` SHALL decide how every bucket of its rate-limit client counts, for every subscriber. Default SHALL be `slidingWindow` (`requests` per rolling `window`, honouring `rateLimitSyncRate`). Actions, the walk, precedence, `Retry-After` rounding, and the failure action SHALL be the same under both algorithms. The README SHALL state what each algorithm does with `requests`, `window`, `burst`, and a hit over the limit.

#### Scenario: Subscribers use the owner's algorithm
- **WHEN** the owner sets `rateLimitAlgorithm: tokenBucket` and a subscriber sets `rateLimitAlgorithm: slidingWindow` without `rateLimitEnabled`
- **THEN** requests through the subscriber are counted by token buckets

### Requirement: A token bucket refills at requests per window and holds up to burst
With `tokenBucket`, each bucket SHALL be a token bucket in Redis that holds at most `burst` tokens (default `requests`), starts full, and refills at `requests` / `window` tokens per second. A charged hit takes one token; a hit that finds no whole token SHALL be answered at once and SHALL NOT consume a token (no queuing). Every charged hit SHALL be one Redis round trip. A bucket's state SHALL expire after a full refill (`burst` × `window` / `requests`, rounded up to whole seconds, at least 1s).

#### Scenario: Burst requests pass at once, then the refill rate applies
- **WHEN** `rateLimitAlgorithm` is `tokenBucket` and a `ratelimit` bucket has `requests: 1`, `window: 10s`, and `burst: 3`
- **AND** one client sends 4 requests at once
- **THEN** the first 3 reach the backend and the fourth is answered by the bucket
- **AND** 10 seconds later one more request from that client reaches the backend

#### Scenario: Default burst equals requests
- **WHEN** `rateLimitAlgorithm` is `tokenBucket` and a bucket has `requests: 5`, `window: 1m`, and no `burst`
- **THEN** a client that sends 6 requests at once gets the sixth answered by the bucket
