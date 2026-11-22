## RENAMED Requirements

- FROM: `### Requirement: The rate-limit counter is opened once per middleware and Redis settings`
- TO: `### Requirement: The rate-limit client is opened on the owner with its policy`

## MODIFIED Requirements

### Requirement: The rate-limit client is opened on the owner with its policy
When `rateLimitEnabled` is true, `New` SHALL open one rate-limit client on the bind context it already uses for the other legs, before it returns the handler. That middleware is the owner. The client SHALL hold the Redis counter, the owner's compiled `rateLimitBuckets`, and the owner's `rateLimitFailureAction`, `rateLimitStatusCode`, and `rateLimitResponseHeaders` (the policy). It SHALL be held in the process reclaim table under an ownership key built from the owner's Traefik middleware name, `rateLimitRedisHost`, the resolved Redis password, `rateLimitRedisDatabase`, the parsed `rateLimitSyncRate`, `rateLimitAlgorithm`, the bucket rows, and the three policy settings. `rateLimitInstanceName` and `bouncerEnabled` MUST NOT be part of that key. A reload that keeps those values SHALL reuse the same client within the table grace. A change to any of them SHALL open a new client; it SHALL NOT reset the Redis counters, so a bucket keeps its count unless it is renamed.

The client SHALL be published under the owner's `rateLimitInstanceName` (`core_plugin_middleware_instance-slots`). Every router that subscribes to that name SHALL charge the owner's buckets and answer with the owner's policy. A router SHALL read its own `rateLimitBuckets`, `rateLimitFailureAction`, `rateLimitStatusCode`, `rateLimitResponseHeaders`, and `rateLimitRedis*` only when it has `rateLimitEnabled`; on any other router they SHALL be ignored.

When `rateLimitEnabled` is false, `New` SHALL NOT open a client, SHALL NOT dial Redis, and SHALL NOT read `rateLimitRedisPasswordFile`.

The Redis password SHALL be read with the file-then-field lookup (`rateLimitRedisPasswordFile`, then `rateLimitRedisPassword`). `rateLimitRedis*` settings SHALL NOT fall back to `lapiRedis*` settings.

When the client cannot be created (invalid Redis settings), `New` SHALL fail and release the holders it already opened. An unreachable Redis server at start SHALL NOT fail `New`; it is a request-time failure.

#### Scenario: Two subscribers share one client and one policy
- **WHEN** owner `rl-owner` publishes rate-limit instance `shared` with bucket `login` allowing 3 requests per minute and `rateLimitStatusCode` 503
- **AND** middlewares `app-a` and `app-b` set `bouncerEnabled` and `rateLimitInstanceName: shared` and no other `rateLimit*` setting
- **THEN** one rate-limit client is opened
- **AND** the fourth request of a client through `app-a` answers 503, and so does the fourth through `app-b`

#### Scenario: Two routers share one counter
- **WHEN** two Traefik routers use the same subscribing middleware
- **THEN** one rate-limit client is bound to both
- **AND** a hit on either router counts against the same bucket counter

#### Scenario: Disabled leg opens nothing
- **WHEN** `rateLimitEnabled` is false and `rateLimitRedisPasswordFile` points at a missing file
- **THEN** `New` succeeds
- **AND** no rate-limit client is opened

#### Scenario: Changed sync rate opens a new counter
- **WHEN** a reload changes the owner's `rateLimitSyncRate` from `200ms` to `0`
- **THEN** the new configuration uses a new client

#### Scenario: Changed algorithm opens a new client
- **WHEN** a reload changes the owner's `rateLimitAlgorithm` from `slidingWindow` to `tokenBucket`
- **THEN** the owner publishes a new client and its subscribers bind it

#### Scenario: Bucket edit opens a new client and keeps the count
- **WHEN** an owner reload changes bucket `login` from 3 to 5 requests per minute
- **AND** a client already sent 3 requests through a subscriber in the current window
- **THEN** the owner publishes a new client and its subscribers bind it
- **AND** that client's next 2 requests in the window reach the backend and the third is answered by `login`

#### Scenario: A subscriber's own rate-limit settings are ignored
- **WHEN** a subscriber with `rateLimitEnabled` false sets `rateLimitBuckets` and `rateLimitStatusCode: 418`
- **THEN** its requests are charged to the owner's buckets
- **AND** an over-limit request answers the owner's `rateLimitStatusCode`

#### Scenario: Unreachable Redis at start does not fail New
- **WHEN** `rateLimitEnabled` is true and nothing listens at `rateLimitRedisHost`
- **THEN** `New` returns a handler

### Requirement: Counters are shared across replicas through Redis keys
Each bucket counter SHALL live in Redis under the key `rl:<middleware name>:<bucket name>:<key hash>` followed by the suffix of the owner's algorithm: `:<window start>` (one string per window) with `slidingWindow`, `:tb` (one hash holding the tokens and the last refill time) with `tokenBucket`. The two key sets SHALL NOT overlap, so switching `rateLimitAlgorithm` starts every bucket from zero and never reads the other algorithm's value. `<middleware name>` SHALL be the Traefik name of the subscribing middleware that charges the request, not the owner's name. `<key hash>` SHALL be the first 16 hexadecimal characters of the SHA-256 of the bucket's key parts joined with a NUL byte. A bucket with an empty `key` list SHALL hash the empty string and so has one counter. Raw header, cookie, query, or path values SHALL NOT appear in Redis keys.

Two Traefik processes that run a subscribing middleware with the same name against the same Redis SHALL count into the same keys. Two Traefik routers that use the same subscribing middleware SHALL share its counters. Two subscribing middlewares with different names SHALL NOT share counters, even when they subscribe to the same client and their bucket names are equal.

#### Scenario: Two replicas share a counter
- **WHEN** two Traefik processes run subscribing middleware `edge` against the same Redis
- **AND** bucket `login` allows 5 requests per minute per client address
- **AND** one client sends 3 requests to each process within the window
- **THEN** at least one of those 6 requests is answered by `login`, given `rateLimitSyncRate` `0`

#### Scenario: Different middleware names do not share
- **WHEN** subscribing middlewares `edge-a` and `edge-b` both charge bucket `login`
- **THEN** a hit through `edge-a` does not count against `edge-b`

#### Scenario: Subscribers of one policy keep separate budgets
- **WHEN** middlewares `app-a` and `app-b` subscribe to the same rate-limit instance with bucket `login` allowing 3 requests per minute
- **AND** one client sends 4 requests through `app-a`
- **THEN** the fourth is answered by `login`
- **AND** the same client's next 3 requests through `app-b` reach the backend

#### Scenario: Header value is not stored in clear
- **WHEN** a bucket keys on header `Authorization`
- **THEN** the Redis key contains a hash and not the header value

#### Scenario: Token-bucket key does not collide with sliding-window keys
- **WHEN** subscriber `edge` charges bucket `login` with `tokenBucket`
- **THEN** the counter key is `rl:edge:login:<key hash>:tb`
- **AND** no `rl:edge:login:<key hash>:<window start>` key is written

### Requirement: Sync rate trades accuracy for Redis round trips
`rateLimitSyncRate` SHALL be a Go duration string. It SHALL be read only when the owner's `rateLimitAlgorithm` is `slidingWindow`; with `tokenBucket` every charged hit is one Redis round trip before the verdict whatever its value, and the value SHALL still be validated. `0` SHALL mean exact mode: every charged hit is one increment in Redis before the verdict. A positive value SHALL mean buffered mode: hits are counted locally, a key is read from Redis the first time this process sees it in a window, and local increments are written to Redis on that interval. A positive value below 20ms SHALL behave as 20ms. Default SHALL be `200ms`.

In buffered mode, one replica MAY admit more than the limit by up to the hits the other replicas have not flushed yet. The README SHALL state this bound and that `tokenBucket` does not read the sync rate.

#### Scenario: Exact mode denies at the limit on one process
- **WHEN** `rateLimitSyncRate` is `0` and a bucket allows 5 requests per minute
- **THEN** the sixth request from one client in that minute is denied

#### Scenario: Buffered mode does not call Redis on every hit
- **WHEN** `rateLimitSyncRate` is `200ms` and one client sends many requests to one bucket within 200ms
- **THEN** Redis receives at most one read for that key and one write per flush interval for that key

#### Scenario: Token bucket ignores the sync rate
- **WHEN** `rateLimitAlgorithm` is `tokenBucket` and `rateLimitSyncRate` is `200ms`
- **THEN** every charged hit is counted in Redis before its verdict

### Requirement: A Redis failure applies the rate-limit failure action within a fixed time budget
The whole rate-limit step of one request SHALL run under a deadline of 250ms derived from the request context. Each Redis command SHALL use at most that remaining budget, including connection dial and retries. When the request context ends first, the step SHALL stop with that error.

In buffered mode (`rateLimitSyncRate` > 0) a Redis outage SHALL NOT be an error: `windowcounter` (utilities v1.0.9+) keeps counting on this replica, starting from zero for a key it has not read yet, answers with a nil error, skips Redis for one sync rate after a failure, and retries after that. Buckets SHALL then answer on this replica's local count, and `rateLimitFailureAction` SHALL NOT apply.

With `tokenBucket` there is no buffered mode: every take is one Redis round trip, so a Redis outage is an error as in exact mode.

When counting a hit returns an error (in exact mode or with `tokenBucket`: Redis unreachable or timeout; in every mode: the deadline or the request context), the step SHALL stop evaluating buckets and SHALL apply the owner's `rateLimitFailureAction`, even when a `captcha` bucket was already over its limit in that walk:

- `passthrough` (default): the request continues to the AppSec step as if no bucket answered. No remediation header. No drop is counted.
- `ban`: the ban page with `bouncerRemediationStatusCode`, remediation header `ban:ratelimit-failure`, drop origin `plugin:ratelimit_failure`.
- `captcha`: the subscribing router's captcha gate, remediation header `captcha:ratelimit-failure`, drop origin `plugin:ratelimit_failure`. A valid gate cookie lets the request continue. A request matched by a `bypassCaptcha` action rule continues. A router without a usable captcha client serves a ban (`ban:captcha-downgrade`) and logs it as `core_plugin_ratelimit_buckets` "Rate-limit captcha downgrades log on transitions" says, never WARN `crowdsec bouncer captcha unsubscribed`.

When the counter returns an error together with a local verdict, the failure action SHALL decide and the local verdict SHALL be ignored.

Each failing request SHALL log at DEBUG with the client address and the error. The plugin MUST NOT log a WARN or ERROR per failing request.

#### Scenario: Unreachable Redis with passthrough lets the request through
- **WHEN** `rateLimitSyncRate` is `0`, `rateLimitFailureAction` is `passthrough`, and Redis is unreachable
- **THEN** the request reaches the backend
- **AND** the request spends no more than the 250ms budget in the rate-limit step

#### Scenario: Unreachable Redis with ban answers the ban page
- **WHEN** `rateLimitSyncRate` is `0`, `rateLimitFailureAction` is `ban`, and Redis is unreachable
- **AND** `bouncerRemediationHeadersCustomName` is `X-Remediation`
- **THEN** the response status is `bouncerRemediationStatusCode`
- **AND** `X-Remediation` is `ban:ratelimit-failure`

#### Scenario: Unreachable Redis with a token bucket applies the failure action
- **WHEN** `rateLimitAlgorithm` is `tokenBucket`, `rateLimitSyncRate` is `200ms`, `rateLimitFailureAction` is `ban`, and Redis is unreachable
- **THEN** the response is the ban page with remediation header `ban:ratelimit-failure`

#### Scenario: Unreachable Redis in buffered mode keeps the local limit
- **WHEN** `rateLimitSyncRate` is `200ms`, `rateLimitFailureAction` is `ban`, Redis is unreachable, and a `ratelimit` bucket allows 1 request per minute
- **THEN** the first request from a client reaches the backend
- **AND** the second is answered with `rateLimitStatusCode` and remediation header `ban:ratelimit:<bucket>`, not `ban:ratelimit-failure`

#### Scenario: Failure-action captcha honours bypassCaptcha
- **WHEN** `rateLimitSyncRate` is `0`, `rateLimitFailureAction` is `captcha`, and Redis is unreachable
- **AND** a `bypassCaptcha` action rule matches the request
- **THEN** the request continues to the AppSec step

#### Scenario: Failure-action captcha on a router without a captcha does not warn per request
- **WHEN** the owner's `rateLimitFailureAction` is `captcha`, Redis is unreachable in exact mode, and the subscribing router has no captcha instance name
- **AND** two requests reach the rate-limit step
- **THEN** both are answered with `ban:captcha-downgrade`
- **AND** WARN `crowdsec bouncer captcha unsubscribed` is not logged

#### Scenario: Slow Redis does not hold the request past the budget
- **WHEN** Redis accepts the connection but does not answer
- **THEN** the rate-limit step returns within the 250ms budget
- **AND** in exact mode it applies `rateLimitFailureAction`

## ADDED Requirements

### Requirement: A subscriber logs the loss and return of its rate-limit owner
A rate-limit subscriber SHALL log WARN `crowdsec bouncer rate limit owner unavailable` (`traefikName`, `instanceName`) once each time it moves to no published rate-limit client. It SHALL log INFO `crowdsec bouncer rate limit owner available` (`traefikName`, `instanceName`, the bound client's `incarnation`) once, on the first bind after that WARN. Neither line SHALL be logged per request, on a repeated delivery of the same state, or when one client replaces another.

#### Scenario: Owner removed logs one WARN
- **WHEN** subscriber `app-a` of instance `shared` is bound and the owner of `shared` is removed
- **AND** three requests then reach `app-a`
- **THEN** WARN `crowdsec bouncer rate limit owner unavailable` with `traefikName` `app-a` and `instanceName` `shared` is logged once
- **AND** the three requests reach the backend uncharged

#### Scenario: Owner restored logs one INFO
- **WHEN** the owner of `shared` publishes again after that WARN
- **THEN** INFO `crowdsec bouncer rate limit owner available` with the new client's `incarnation` is logged once
- **AND** publishing the same client again or replacing it by a new one logs neither line

#### Scenario: Subscriber that starts before its owner
- **WHEN** under Traefik's interpreter a subscriber of `shared` starts before any owner publishes `shared`
- **THEN** it logs WARN `crowdsec bouncer rate limit owner unavailable` once
- **AND** when the owner publishes, it logs INFO `crowdsec bouncer rate limit owner available` once
- **AND** compiled Go, which does not deliver that first empty value, logs neither line

### Requirement: The owner-unavailable WARN is pending per middleware name across reloads
The owner-unavailable WARN SHALL stay pending per Traefik middleware name for the process lifetime, not per router instance. While it is pending, no instance of that name SHALL log a second WARN for the same rate-limit instance name, and the first bind of any instance of that name SHALL log the INFO that answers it. A rebuild on another instance name or without the rate limit follows the scenarios below.

#### Scenario: Reload rebuilds the subscriber during the outage
- **WHEN** subscriber `app-a` of instance `shared` has logged WARN `crowdsec bouncer rate limit owner unavailable` and a Traefik reload builds a new `app-a` instance while `shared` is still unpublished
- **THEN** the new instance logs no second WARN, also under Traefik's interpreter where its first delivery is the empty value
- **AND** when a reload publishes `shared` again and builds `app-a` after the owner, the new instance's first bind logs INFO `crowdsec bouncer rate limit owner available` once with the bound client's `incarnation`
- **AND** a later bind of any other `app-a` instance logs neither line, and the next loss of `shared` logs WARN again

#### Scenario: Reload moves the subscriber to another instance name
- **WHEN** `app-a` has a WARN pending for `shared` and a reload builds `app-a` on instance `other`, also unpublished
- **THEN** WARN `crowdsec bouncer rate limit owner unavailable` with `instanceName` `other` is logged once
- **AND** when `other` publishes, INFO `crowdsec bouncer rate limit owner available` with `instanceName` `other` is logged once, and a later `app-a` bound to `shared` logs no INFO

#### Scenario: Reload drops the rate limit from the subscriber
- **WHEN** `app-a` has a WARN pending and a reload builds `app-a` without `rateLimitInstanceName`
- **THEN** no line is logged and the pending WARN is dropped
- **AND** a later `app-a` that binds a rate-limit client logs no INFO
