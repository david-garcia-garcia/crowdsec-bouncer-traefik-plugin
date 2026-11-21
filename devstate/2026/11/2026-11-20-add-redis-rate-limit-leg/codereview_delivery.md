# Delivery

## Motivation

The plugin's legs answer CrowdSec decisions (LAPI), request inspection (AppSec, ModSec), and its own `bouncerActionRules`. None of them limits how often one client, token, or tenant calls a route. The owner wants this middleware to be the single edge WAF, so a rate limit belongs in it as another leg, not in a separate middleware.

The gap has two parts. First, nothing counts requests. A client can send `POST /login` as fast as it likes. Every one of those requests reaches AppSec, ModSec, and the backend until CrowdSec has read the logs and issued a decision. Second, the ask names two properties that a per-process counter cannot give. The counters must be shared through Redis, so that a limit of 5 per minute stays 5 when several Traefik replicas serve the same middleware. Buckets must also be named, and each must set two things apart: which requests count (method, path, host, header, cookie) and what the counter is per (client IP or network, header, cookie, query parameter, part of the path, host, method).

If this stays open, operators of this plugin have no way to cap request rates from it. They either run a second middleware outside the WAF pipeline, whose counts do not respect this plugin's trusted clients, action rules, or verdict header, or they let floods through to the inspection legs and the backend.

Priority: P2 — real operator pain (no rate limit in the edge WAF), with a workaround outside the plugin.

## Implementation

A new package, `pkg/ratelimit`, holds the leg. Its Redis-backed counter is the `windowcounter` sliding window from `traefik-middleware-utilities`. That package is now vendored at the `v1.0.7` already pinned in `go.mod`, with no module bump. `plugin.New` opens the counter only when `rateLimitEnabled` is true, through `reclaim.OpenWithHooks`. The counter is keyed on the middleware name plus the Redis host, password, database, and sync rate, so routers of one middleware with the same settings share one counter. The counter's Sleep, Wake, and Close hooks follow the reclaim lifecycle, and Close also closes the Redis client. Opening it does not dial Redis. An unreachable Redis is a request-time error, not a startup failure. The leg has no instance name, alias, or Watch. A failed `New` releases the holder. The counter reaches the router through `Bouncer.AttachRateLimit` before the handler is returned.

`bouncer.New` compiles the buckets once with `ratelimit.NewBucketSet`. The bucket predicates are the `bouncerActionRules` predicates (`httprule.Rule`, RE2), written flat on the bucket row. They compile through a new `httprule.NewWithCatchAll`, so a bucket with no predicate matches every request. Bucket names use the same rules as action-rule names (the shared `httprule.CompileRowName`: trimmed, non-empty, no colon, unique). The window must be a whole number of seconds and at least 1s. `requests` must be at least 1. Each key part is checked for a known source, a `name` where one is required, an IP prefix (allowed on `ip` only), and a `pattern` with a capture group. `algorithm: tokenBucket`, `burst`, bucket `action: captcha`, and `rateLimitStore` other than `redis` fail validation with a "not supported in this version" error, so Traefik's decode cannot drop them silently. `ValidateParams` checks rate-limit settings only when the leg is enabled.

On the request path, a new `serveRateLimit` step runs after `serveLAPI` and before `serveAppSec`, which comes before `serveModSec`. That means trusted clients, action-rule bans, and requests LAPI already banned or challenged are never counted. One 250ms context covers every bucket and every Redis command of the step. The Redis client has a 200ms dial timeout and a pool of 8. `Charge` walks the matching buckets in list order:

- It reads the key parts. The client IP comes from the resolved address, masked by the new `ip.MaskPrefix`. The host comes from the now-exported `httprule.RequestHostname`. A missing value skips the bucket, including its `final`.
- It hashes the parts into `rl:<middleware>:<bucket>:<16 hex of SHA-256>`, so raw header, cookie, or query values never reach Redis.
- It counts the hit, then compares. A denied hit still counts.

The first `deny` bucket over its limit stops the walk. It answers through `handleBanStatusServeHTTP` with `rateLimitStatusCode` (default 429), with `Retry-After` set to the seconds until the bucket's current window ends (at least 1). The verdict header is `ban:ratelimit:<bucket>`: `formatRemediationHeader` now gives a third field to reason `ratelimit` as well as to `lapi`, with CR, LF, and TAB stripped. A drop is recorded under `plugin:ratelimit:<bucket>`. If a `captcha` action rule also matched, a WARN says it lost. A `log` bucket over its limit only logs INFO `crowdsec bouncer rate limit exceeded`. `final: true` stops after that bucket.

The first counter error stops the walk and applies `rateLimitFailureAction`:

- `passthrough` (the default) continues the request.
- `ban` serves the ban page with `bouncerRemediationStatusCode` and the header `ban:ratelimit-failure`.
- `captcha` honours `bypassCaptcha` and falls back to a ban when the router has no captcha.

Failure drops are recorded under `plugin:ratelimit_failure`. A new action token, `bypassRateLimit`, sets `SkipRateLimit` in `ActionSet.Fold`, under the same ambiguous-path guard as the other skip tokens. `bypass` does not skip the rate limit.

Proof:

- Unit tests in `pkg/ratelimit`, `pkg/bouncer`, `pkg/configuration`, `pkg/httprule`, `pkg/ip`, and the plugin root.
- A Yaegi test of open, charge, and close.
- `realredis` Go tests against Dragonfly, which CI's realredis job and `make test_realredis` now run.
- A real-stack Pester file on Traefik's file provider. It covers deny with `Retry-After`, per-IP separation, the `bypassRateLimit` health path, the cscli drop under `plugin:ratelimit:login`, a log bucket, and an unreachable Redis with failure actions `passthrough` and `ban`.

## What this changes
**Operators.** A new opt-in leg: set `rateLimitEnabled: true` and add `rateLimitBuckets`; you can also set `rateLimitRedisHost` (default `redis:6379`, does not fall back to `lapiRedisHost`), `rateLimitRedisPassword`/`rateLimitRedisPasswordFile`, `rateLimitRedisDatabase`, `rateLimitSyncRate` (default `200ms`, `0` = exact), `rateLimitFailureAction` (default `passthrough`), `rateLimitStatusCode` (default 429), `rateLimitResponseHeaders`, the `bypassRateLimit` rule token, and watch the new header values `ban:ratelimit:<bucket>`, `ban:ratelimit-failure`, `captcha:ratelimit-failure` and drop origins `plugin:ratelimit:<bucket>`, `plugin:ratelimit_failure`; the bucket list is proven on the file provider only.
**Admin users.** None.
**Developers.** New package `pkg/ratelimit` (`BucketRule`, `KeyPart`, `Counter`, `Open`, `OwnershipKey`, `StepBudget`), new exports `httprule.CompileRowName`, `httprule.NewWithCatchAll`, `httprule.RequestHostname`, `ip.MaskPrefix`, `lapi.OriginPluginRateLimit*`, `Bouncer.AttachRateLimit`, `configuration.RateLimitSyncRateDuration`, a vendored `windowcounter`, and `ServeHTTP` now runs the rate-limit step between LAPI and AppSec.
**End users.** On routes where an operator enables a `deny` bucket, a client over the limit now gets the ban page with HTTP 429 (or the configured status) and a `Retry-After` header.
