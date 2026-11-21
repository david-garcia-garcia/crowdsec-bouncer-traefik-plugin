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

## Merge readiness
In progress. 1 items remain.

Priority: P2 — real operator pain (no rate limit in the edge WAF), with a workaround outside the plugin.
Reviewed head: 6ca0c573
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Not ready |
| CI proof | 1/6 | not seen |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-11-20-add-redis-rate-limit-leg pushed | `git` |
| OpenSpec | add-redis-rate-limit-leg | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/228 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [build_e2e_pester_crowdsec-stack](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/openspec/changes/add-redis-rate-limit-leg/proposal.md) — modified
- [core_plugin_lapi_usage-metrics](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/openspec/changes/add-redis-rate-limit-leg/proposal.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/openspec/changes/add-redis-rate-limit-leg/proposal.md) — modified
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/openspec/changes/add-redis-rate-limit-leg/proposal.md) — modified
- [core_plugin_ratelimit_buckets](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/openspec/changes/add-redis-rate-limit-leg/proposal.md) — added
- [core_plugin_ratelimit_client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/openspec/changes/add-redis-rate-limit-leg/proposal.md) — added


## Deviations from the ask
- taken: each bucket carries `match: {method, path, host, headers, cookies}`. → the same `httprule.Rule` predicates are squashed onto the bucket row (`name`, `path`, `host`, …, `key`, `requests`, `window`, `action`), exactly as a `bouncerActionRules` row carries them. `match` and `key` stay separate concepts; only the nesting goes. — `pkg/httprule/action.go (ActionRule embeds Rule with mapstructure:",squash")` — one authoring shape for "which requests" across the plugin, and one less nesting level in Traefik plugin config, where only list → object → list depth is proven by the existing e2e.. Requester: not asked.


## Follow-up issues
- [ ] [Extract a common leg abstraction from `plugin.go` and `Bouncer`](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/knowledge/debt/2026-11-20-extract-common-leg-abstraction.md) — each published leg is copied by hand into five places in `plugin.go` and `Bouncer`; the owner asked to suggest a shared leg unit before the next leg, and the Open-only rate-limit leg does not need it.


## How this fits together
Ticket 2026-11-20-add-redis-rate-limit-leg on branch 2026-11-20-add-redis-rate-limit-leg targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/228; CI not seen.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Does the existing `bypass` action also skip the rate limit? | additive asked — new `bypassRateLimit` token and `SkipRateLimit` field in `pkg/httprule/action.go`; requirement semantics 5 and open decision 1 | assumed — no. Only `bypassRateLimit` skips the rate limit; `bypass` keeps meaning "skip LAPI and AppSec". The `Fold` skip guard change has 1 caller (`pkg/bouncer/bouncer.go:196`). | explore |


## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/devstate/staging/2026/11/2026-11-20-add-redis-rate-limit-leg/codereview_standards.md) — 6 total, 0 pending, 5 completed, 1 skipped
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/devstate/staging/2026/11/2026-11-20-add-redis-rate-limit-leg/codereview_nitpicks.md) — 5 total, 0 pending, 3 completed, 2 skipped
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/devstate/staging/2026/11/2026-11-20-add-redis-rate-limit-leg/codereview_spec.md) — 2 total, 0 pending, 2 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/devstate/staging/2026/11/2026-11-20-add-redis-rate-limit-leg/codereview_scope.md) — 2 total, 0 pending, 0 completed, 2 skipped
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/devstate/staging/2026/11/2026-11-20-add-redis-rate-limit-leg/codereview_security.md) — 3 total, 0 pending, 1 completed, 2 skipped
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/devstate/staging/2026/11/2026-11-20-add-redis-rate-limit-leg/codereview_performance.md) — 3 total, 0 pending, 1 completed, 2 skipped
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/devstate/staging/2026/11/2026-11-20-add-redis-rate-limit-leg/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/devstate/staging/2026/11/2026-11-20-add-redis-rate-limit-leg/codereview_coverage.md) — 5 total, 0 pending, 1 completed, 4 skipped


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 2 added / 4 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 6ca0c5738e4e41816d98fdd4b41def07614f66ac | Card must match the branch you measured |

### Stored data model
- **New store**: Redis (the rate-limit Redis: `rateLimitRedisHost`, `rateLimitRedisDatabase`, `rateLimitRedisPassword`/`File`; it is a separate client from the decision-cache Redis, `plugin.go:189-207`, `pkg/ratelimit/client.go:99-113`). New key family: sliding-window hit counters.
  - Key: `rl:<middlewareName>:<bucketName>:<hash16>:<windowStartUnix>`. `rl:` + middleware + bucket + the first 16 hex characters of SHA-256 over the key-part values joined by NUL (`pkg/ratelimit/key.go:17-19,110-112`). The window start is appended by the counter (`windowcounter/limiter.go:108-109,117-118,545-546`). `middlewareName` is the Traefik middleware name (`pkg/bouncer/bouncer_serve_ratelimit.go:31`). Raw key-part values (IP, header, cookie, query, path, host, method) are not written. Only the hash is.
  - Fields: one integer per key, the hit count for that window. It is stored as a decimal string by `INCR`/`INCRBY` and read back with `GET` + `strconv.ParseInt` (a miss reads as 0) (`limiter.go:310-322`).
  - TTL: `syncRate=0` (exact mode) runs `INCR`, then `EXPIRE key 2*window` on the first hit (`limiter.go:115,163-168`). `syncRate>0` (buffered, default `200ms`) runs a Lua `EVAL` of `INCRBY key delta` plus `EXPIREAT key windowStart+2*window`, but only when the key did not already exist (`limiter.go:19-22,121,484-487`).
  - Writers: `BucketSet.Charge` → `Client.Take` → `Limiter.Take`, once per matching bucket per request (`pkg/ratelimit/charge.go:42-56`, `client.go:125-126`). Buffered deltas are also flushed by the flush timer, on `Sleep`, and on `Close` (`limiter.go:330-331,346-354,376-377`). Readers: the same limiter only. It runs `GET` on the current and previous window keys. No other component reads `rl:*`.
  - migration: not applicable. Redis is schemaless, and keys are created on first `INCR`/`EVAL` by the shipped code itself (`limiter.go:163,487`). Nothing to deploy.
  - Rollback: the previous version neither reads nor writes `rl:*`. Leftover keys expire by their own TTL (at most about 3 windows after the window start). No red flag.
- Not persistent, so not listed as stores: the reclaim-table key `ratelimit:owner:<fnv64>` is process memory (`client.go:20,72,80`). The buffered `windows` map dies with the process. Usage-metrics origins `plugin:ratelimit:<bucket>` and `plugin:ratelimit_failure` are new label values on the existing LAPI metrics push, with no field change (`pkg/lapi/client_metrics.go`, part.03).
