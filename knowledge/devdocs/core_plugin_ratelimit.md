# Rate-limit leg

## Language

**Rate-limit Client**:
The reclaim value of the rate-limit leg: one vendored `windowcounter.Limiter` plus the `simpleredis` client it writes through. Opened by ownership key (middleware name, `rateLimitRedisHost`, resolved password, `rateLimitRedisDatabase`, parsed `rateLimitSyncRate`). Never published under an instance name; no alias, no Watch. It is the production `ratelimit.Counter`.
_Avoid_: rate limiter instance, `rateLimitInstanceName`, publishing it with `SetAlias`, a Bouncer-owned Limiter, `lapiRedis*` fallback

**Bucket**:
One row of `rateLimitBuckets`: a unique colon-free `name`, the `httprule.Rule` predicates flat on the row (no predicate = every request), a `key` list, `requests` per `window`, `action` (`deny` | `log`), and `final`. Compiled once into a `ratelimit.BucketSet`.
_Avoid_: rule (that is an action rule), a nested `match:` object, `limit`, token bucket, per-bucket captcha

**Counter key**:
`rl:<middleware name>:<bucket>:<first 16 hex of SHA-256 of the key part values joined by NUL>`; `windowcounter` appends `:<window start>`. Raw request values never reach Redis.
_Avoid_: the client IP as the Redis key, the ownership key, `rl:<bucket>` without the middleware name

**Step budget**:
`ratelimit.StepBudget` (250ms): one `context.WithTimeout` around the whole rate-limit step of a request, every bucket and every Redis command (dial and retries included). The Client's `simpleredis` `CommandTimeout` is the same value.
_Avoid_: a per-bucket timeout, a public timeout knob, decisionstore's 1s command timeout

## Overview

`pkg/ratelimit` owns the leg: authoring types (`BucketRule`, `KeyPart`), compile (`NewBucketSet`, used by `ValidateParams` and `bouncer.New`), evaluation (`(*BucketSet).Charge`), the `Counter` interface, and the Redis-backed `Client` (`Open`, `OwnershipKey`, `RedisSettings`). It does not import `pkg/configuration`; configuration imports it for `Config.RateLimitBuckets`, the way it imports `httprule.ActionRule`. The Bouncer step is `serveRateLimit` in `pkg/bouncer/bouncer_serve_ratelimit.go`, between `serveLAPI` and `serveAppSec`. Specs: `core_plugin_ratelimit_client`, `core_plugin_ratelimit_buckets`.

## How to use

- `plugin.New` calls `openRateLimit(bindCtx, &config, log, name)` after `openOwned` and before `claimOwned`, so a later failure releases it with the other holders. It returns nil when `rateLimitEnabled` is false and then reads no password file and dials nothing. After `bouncer.New`, `route.AttachRateLimit(client)` sets a plain field before the handler is returned.
- Resolve the password with `configuration.GetVariable(config, "RateLimitRedisPassword")` and the sync rate with `configuration.RateLimitSyncRateDuration` — the one parser `ValidateParams` also uses.
- Compile buckets once: `ValidateParams` compiles and discards (`RateLimitBuckets: bucket %d: …`), `bouncer.New` compiles again to store, only when the leg is enabled. Do not compile on the request path.
- Call `Charge(ctx, counter, middlewareName, req.Request, req.IPAddr())` under `context.WithTimeout(req.Context(), ratelimit.StepBudget)`. The client address is the `GetRemoteIP` result on `clientrequest.Request`; do not re-parse `RemoteAddr` or forwarded headers.
- Key part owners: `ip` → `ip.MaskPrefix` on that address; `host` → `httprule.RequestHostname`; `path` → `req.URL.Path`; `header` → `Header.Get`; `cookie` → `req.Cookie`; `query` → `URL.Query()` parsed at most once per `Charge`.
- Read the `Verdict`: `Err` → failure action (`passthrough` | `ban` | `captcha`, the shared `FailureAction*` words, default `passthrough`); `DenyBucket` → `handleBanStatusServeHTTP` with `rateLimitStatusCode`, `Retry-After` from `RetryAfter`, header `ban:ratelimit:<bucket>`, origin `lapi.OriginPluginRateLimit(bucket)`; `Exceeded` → INFO `crowdsec bouncer rate limit exceeded`.
- Unit tests pass a fake `ratelimit.Counter` (`AttachRateLimit` in `pkg/bouncer`, a test type in `pkg/ratelimit`). Real Redis: `go test -tags realredis ./pkg/ratelimit` (`build_e2e_go-redis.md`).

## Pattern snippet

```go
ctx, cancel := context.WithTimeout(req.Context(), ratelimit.StepBudget)
defer cancel()
verdict := b.rateLimitBuckets.Charge(ctx, b.rateLimitCounter, b.name, req.Request, req.IPAddr())
if verdict.Err != nil {
	return b.applyRateLimitFailureAction(rw, req, match)
}
```

## Key files

- `pkg/ratelimit/`
- `pkg/bouncer/bouncer_serve_ratelimit.go`
- `pkg/configuration/configuration.go`
- `plugin.go`
- `vendor/github.com/david-garcia-garcia/traefik-middleware-utilities/windowcounter/limiter.go`

## Gotchas

- `windowcounter` at the `v1.0.7` pin is vendored as published. Do not patch `vendor/`; CI re-vendors. Buffered mode (`rateLimitSyncRate` > 0) keeps a stale previous window across replicas (upstream PR #63) and exact mode does not retry a failed first `EXPIRE` (PR #60): `knowledge/debt/2026-11-20-bump-utilities-windowcounter-fixes.md`.
- Buffered mode returns a local verdict together with an error during an outage. The error wins: the failure action decides.
- A hit is counted even when it is denied, so a client that keeps sending stays limited.
- Windows are whole seconds of at least 1s; `windowcounter` would only fail at `Take`, so `NewBucketSet` rejects them at startup.
- `Retry-After` is the time to the window boundary on the `unix / window` grid, not a promise that the next request passes.
- A `path`-matched bucket has the same alternate-encoding gap as ban and captcha rules (`knowledge/debt/2026-11-15-ban-captcha-path-rules-ambiguous-path-evasion.md`). A catch-all bucket does not, unless an earlier `final` bucket with a `path` condition matches the encoded path and stops the walk before it.
- Only the file provider is proven to decode the bucket list (real-stack `config/dynamic/rate-limit.yml`). Traefik drops unknown keys, which is why `algorithm`, `burst`, and `rateLimitStore` exist only to reject `tokenBucket`, a set burst, and `memory`.
- A blackholed Redis costs every request that needs Redis up to `StepBudget` for the whole outage; there is no backoff gate (`knowledge/debt/2026-11-20-rate-limit-redis-backoff-gate.md`).
