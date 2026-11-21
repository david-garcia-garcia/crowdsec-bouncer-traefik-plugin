## Purpose

The rate-limit leg keeps its sliding-window counters in Redis so every Traefik replica that runs the same middleware shares one count. This capability owns when that counter is opened and shared, the Redis key layout, the sync rate, the time a request may spend on Redis, and what a Redis failure does to the request.

## Requirements

### Requirement: The rate-limit counter is opened once per middleware and Redis settings
When `rateLimitEnabled` is true, `New` SHALL open one rate-limit counter on the bind context it already uses for the other legs, before it returns the handler. The counter SHALL be held in the process reclaim table under an ownership key built from the Traefik middleware name, `rateLimitRedisHost`, the resolved Redis password, `rateLimitRedisDatabase`, and the parsed `rateLimitSyncRate`. Two routers that use the same middleware SHALL share one counter. A reload that keeps those values SHALL reuse the same counter within the table grace. A change to any of them SHALL open a new counter.

The counter SHALL NOT be published under an instance name and SHALL NOT be watched by another middleware. Bucket rows, `rateLimitFailureAction`, `rateLimitStatusCode`, and `rateLimitResponseHeaders` SHALL NOT be part of the ownership key; they stay per router.

When `rateLimitEnabled` is false, `New` SHALL NOT open a counter, SHALL NOT dial Redis, and SHALL NOT read `rateLimitRedisPasswordFile`.

The Redis password SHALL be read with the file-then-field lookup (`rateLimitRedisPasswordFile`, then `rateLimitRedisPassword`). `rateLimitRedis*` settings SHALL NOT fall back to `lapiRedis*` settings.

When the counter cannot be created (invalid Redis settings), `New` SHALL fail and release the holders it already opened. An unreachable Redis server at start SHALL NOT fail `New`; it is a request-time failure.

#### Scenario: Two routers share one counter
- **WHEN** two routers use the same rate-limit middleware
- **THEN** one counter is opened
- **AND** a hit on either router counts against the same bucket counter

#### Scenario: Disabled leg opens nothing
- **WHEN** `rateLimitEnabled` is false and `rateLimitRedisPasswordFile` points at a missing file
- **THEN** `New` succeeds
- **AND** no rate-limit counter is opened

#### Scenario: Changed sync rate opens a new counter
- **WHEN** a reload changes `rateLimitSyncRate` from `200ms` to `0`
- **THEN** the new configuration uses a new counter

#### Scenario: Unreachable Redis at start does not fail New
- **WHEN** `rateLimitEnabled` is true and nothing listens at `rateLimitRedisHost`
- **THEN** `New` returns a handler

### Requirement: Counters are shared across replicas through Redis keys
Each bucket counter SHALL live in Redis under the key `rl:<middleware name>:<bucket name>:<key hash>` followed by the window start that the sliding window appends. `<key hash>` SHALL be the first 16 hexadecimal characters of the SHA-256 of the bucket's key parts joined with a NUL byte. A bucket with an empty `key` list SHALL hash the empty string and so has one counter. Raw header, cookie, query, or path values SHALL NOT appear in Redis keys.

Two Traefik processes that run a middleware with the same name and the same Redis settings SHALL count into the same keys. Two middlewares with different names SHALL NOT share counters, even when their bucket names are equal.

#### Scenario: Two replicas share a counter
- **WHEN** two Traefik processes run middleware `edge` against the same Redis
- **AND** bucket `login` allows 5 requests per minute per client address
- **AND** one client sends 3 requests to each process within the window
- **THEN** at least one of those 6 requests is denied, given `rateLimitSyncRate` `0`

#### Scenario: Different middleware names do not share
- **WHEN** middlewares `edge-a` and `edge-b` both define bucket `login`
- **THEN** a hit through `edge-a` does not count against `edge-b`

#### Scenario: Header value is not stored in clear
- **WHEN** a bucket keys on header `Authorization`
- **THEN** the Redis key contains a hash and not the header value

### Requirement: Sync rate trades accuracy for Redis round trips
`rateLimitSyncRate` SHALL be a Go duration string. `0` SHALL mean exact mode: every charged hit is one increment in Redis before the verdict. A positive value SHALL mean buffered mode: hits are counted locally, a key is read from Redis the first time this process sees it in a window, and local increments are written to Redis on that interval. A positive value below 20ms SHALL behave as 20ms. Default SHALL be `200ms`.

In buffered mode, one replica MAY admit more than the limit by up to the hits the other replicas have not flushed yet. The README SHALL state this bound.

#### Scenario: Exact mode denies at the limit on one process
- **WHEN** `rateLimitSyncRate` is `0` and a bucket allows 5 requests per minute
- **THEN** the sixth request from one client in that minute is denied

#### Scenario: Buffered mode does not call Redis on every hit
- **WHEN** `rateLimitSyncRate` is `200ms` and one client sends many requests to one bucket within 200ms
- **THEN** Redis receives at most one read for that key and one write per flush interval for that key

### Requirement: A Redis failure applies the rate-limit failure action within a fixed time budget
The whole rate-limit step of one request SHALL run under a deadline of 250ms derived from the request context. Each Redis command SHALL use at most that remaining budget, including connection dial and retries. When the request context ends first, the step SHALL stop with that error.

When counting a hit returns an error (Redis unreachable, timeout, a failed flush retained in buffered mode, or the deadline), the step SHALL stop evaluating buckets and SHALL apply `rateLimitFailureAction`:

- `passthrough` (default): the request continues to the AppSec step as if no bucket denied it. No remediation header. No drop is counted.
- `ban`: the ban page with `bouncerRemediationStatusCode`, remediation header `ban:ratelimit-failure`, drop origin `plugin:ratelimit_failure`.
- `captcha`: the router's captcha gate, remediation header `captcha:ratelimit-failure`, drop origin `plugin:ratelimit_failure`. A valid gate cookie lets the request continue. A request matched by a `bypassCaptcha` action rule continues. A router without a usable captcha client serves a ban (`ban:captcha-downgrade`).

When the counter returns an error together with a local verdict, the failure action SHALL decide and the local verdict SHALL be ignored.

Each failing request SHALL log at DEBUG with the client address and the error. The plugin MUST NOT log a WARN or ERROR per failing request.

#### Scenario: Unreachable Redis with passthrough lets the request through
- **WHEN** `rateLimitFailureAction` is `passthrough` and Redis is unreachable
- **THEN** the request reaches the backend
- **AND** the request spends no more than the 250ms budget in the rate-limit step

#### Scenario: Unreachable Redis with ban answers the ban page
- **WHEN** `rateLimitFailureAction` is `ban` and Redis is unreachable
- **AND** `bouncerRemediationHeadersCustomName` is `X-Remediation`
- **THEN** the response status is `bouncerRemediationStatusCode`
- **AND** `X-Remediation` is `ban:ratelimit-failure`

#### Scenario: Failure-action captcha honours bypassCaptcha
- **WHEN** `rateLimitFailureAction` is `captcha` and Redis is unreachable
- **AND** a `bypassCaptcha` action rule matches the request
- **THEN** the request continues to the AppSec step

#### Scenario: Slow Redis does not hold the request past the budget
- **WHEN** Redis accepts the connection but does not answer
- **THEN** the rate-limit step returns within the 250ms budget and applies `rateLimitFailureAction`
