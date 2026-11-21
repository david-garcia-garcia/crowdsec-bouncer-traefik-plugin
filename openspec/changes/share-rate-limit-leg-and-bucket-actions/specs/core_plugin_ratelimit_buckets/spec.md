## RENAMED Requirements

- FROM: `### Requirement: A deny bucket answers with the rate-limit status and Retry-After`
- TO: `### Requirement: A ratelimit bucket answers with the rate-limit status and Retry-After`

## MODIFIED Requirements

### Requirement: Matching buckets are charged in list order
For a request that reaches the rate-limit step, the plugin SHALL walk the buckets of the rate-limit client the router is bound to, in list order. For each bucket that matches and has a key value, it SHALL count one hit against that bucket's counter, then compare the sliding-window estimate with `requests` per `window`. A hit SHALL be counted even when it is over the limit.

- A `ratelimit` bucket over its limit SHALL answer the request (requirement "A ratelimit bucket answers with the rate-limit status and Retry-After"). Later buckets SHALL NOT be charged.
- A `captcha` bucket over its limit SHALL NOT stop the walk. The first such bucket in list order SHALL be kept, and when the walk ends without a `ratelimit` answer it SHALL answer the request (requirement "A captcha bucket answers with the router's captcha").
- A `log` bucket over its limit SHALL log at INFO `crowdsec bouncer rate limit exceeded` with attributes `ip`, `bucket`, `requests`, and `window`, and evaluation SHALL continue.
- A matching bucket with `final: true` SHALL stop the walk after that bucket, whether or not it was over its limit.
- When the router has a usable captcha client and the request carries a valid captcha gate cookie, every `captcha` bucket SHALL be skipped: it is not charged, cannot answer, and its `final` does not apply. `ratelimit` and `log` buckets SHALL still be charged.
- The answer SHALL follow the precedence `ratelimit` over `captcha` over `log`.
- When no bucket answers, the request SHALL continue to the AppSec step.

`action` SHALL default to `ratelimit`. `final` SHALL default to false. `algorithm` SHALL default to `slidingWindow`.

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
- **WHEN** a `ratelimit` bucket allows 5 requests per minute and one client sends 1 request per second for 2 minutes
- **THEN** that client is answered by the bucket for most of the second minute too, because answered hits are counted

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

When the owner's `rateLimitResponseHeaders` is true (default), the response SHALL carry `Retry-After` with the counter's `RetryAfter` for that hit (`windowcounter.Status`, utilities v1.0.10+): the time until the first whole second at which one more hit on the same key is admitted with no other traffic, sliding-window weight included. It SHALL be rounded up to whole seconds, at least 1. When false, no `Retry-After` is sent. `RateLimit-*` headers SHALL NOT be sent.

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

#### Scenario: Response headers off
- **WHEN** the owner's `rateLimitResponseHeaders` is false and a `ratelimit` bucket answers
- **THEN** the response has no `Retry-After`

## REMOVED Requirements

### Requirement: Bucket values not in this version fail validation
**Reason**: `action` now accepts `ratelimit` (the round-1 `deny`, renamed), `captcha`, and `log`; the block rejected `captcha`. Replaced by "Bucket algorithm, action, and store values are validated".
**Migration**: Rename `action: deny` to `action: ratelimit` (or omit it, the default). `tokenBucket`, `burst`, and `rateLimitStore: memory` stay rejected.

## ADDED Requirements

### Requirement: Bucket algorithm, action, and store values are validated
`algorithm` SHALL accept only `slidingWindow`. `action` SHALL accept only `ratelimit`, `captcha`, and `log`. A row that sets `algorithm: tokenBucket` or `burst` SHALL fail `ValidateParams` with an error that names the row and says the value is not supported in this version. A row whose `action` is any other value, `deny` included, SHALL fail with an error that names the row and the accepted values. `rateLimitStore` SHALL accept only `redis`; `memory` SHALL fail as not supported in this version.

#### Scenario: Token bucket is rejected
- **WHEN** a bucket sets `algorithm: tokenBucket`
- **THEN** `ValidateParams` fails with an error that names `RateLimitBuckets` and `tokenBucket`

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
When the subscribing router has a usable captcha client, a request for one of that captcha's same-origin widget assets (custom provider) and a request that carries the challenge-form marker `crowdsec_captcha_challenge=v1` SHALL skip every bucket: none is charged, none answers, and the failure action does not apply. On a router without a usable captcha client these requests SHALL be charged like any other. The request that follows a solve SHALL be charged like any other.

A widget asset SHALL continue to the AppSec step. A challenge-form POST SHALL be answered by the router's captcha gate when the bound policy can answer with a captcha (a `captcha` bucket, or `rateLimitFailureAction: captcha`) and no `bypassCaptcha` action rule matched: a valid answer gets the 302 solved redirect with header `captcha:solved` and the gate cookie; any other answer gets the challenge page again with header `captcha:ratelimit` (no third field: no bucket answered) and one `captcha` drop under origin `plugin:ratelimit`. Otherwise the POST SHALL continue to the AppSec step. This holds whether or not the router also subscribes to AppSec.

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

#### Scenario: Verification POST on a policy without a captcha answer continues
- **WHEN** the bound policy has only `ratelimit` and `log` buckets and failure action `passthrough`
- **AND** a client posts a form with the marker on a router with a usable captcha
- **THEN** no bucket counter moves and the request continues to the AppSec step

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
