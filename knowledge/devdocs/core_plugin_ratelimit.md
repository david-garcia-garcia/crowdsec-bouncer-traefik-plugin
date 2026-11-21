# Rate-limit leg

## Language

**Rate-limit Client**:
The reclaim value of the rate-limit leg: one vendored `windowcounter.Limiter`, the `simpleredis` client it writes through, and the owner's compiled buckets and policy (`ratelimit.Policy`: failure action, status code, `Retry-After` switch). Opened by the owner (`rateLimitEnabled`) under an ownership key of the middleware name, the Redis settings (`rateLimitRedisHost`, resolved password, `rateLimitRedisDatabase`, parsed `rateLimitSyncRate`), the bucket rows, and the policy; `rateLimitInstanceName` is not in the key. Published under the owner's `rateLimitInstanceName` on reclaim group `ratelimit`. It is the production `ratelimit.Counter`.
_Avoid_: rate limiter instance, a Bouncer-owned Limiter or bucket set, per-subscriber policy, `lapiRedis*` fallback

**Owner / subscriber**:
The owner is the middleware with `rateLimitEnabled`: it Opens and publishes the Client, and only its `rateLimit*` settings are read. A subscriber is any router with `bouncerEnabled` and a `rateLimitInstanceName`: it Watches that name, charges the owner's buckets under its own Traefik name, and answers with the owner's policy. One middleware with both flags and no name owns and subscribes to itself.
_Avoid_: subscriber-side buckets, status, or failure action; filling a subscriber's name

**Bucket**:
One row of `rateLimitBuckets`: a unique colon-free `name`, the `httprule.Rule` predicates flat on the row (no predicate = every request), a `key` list, `requests` per `window`, `action` (`ratelimit` default | `captcha` | `log`; anything else, round-1 `deny` included, fails compile naming the three), and `final`. Compiled once into a `ratelimit.BucketSet`; `HasCaptchaBucket()` says whether a row is `captcha`.
_Avoid_: rule (that is an action rule), a nested `match:` object, `limit`, token bucket, `deny` (the round-1 name of `ratelimit`)

**Walk**:
`(*BucketSet).Charge` over the matching buckets in list order. Precedence `ratelimit` over `captcha` over `log`: a `ratelimit` bucket over its limit returns at once (`Verdict.RateLimit`); the first `captcha` bucket over its limit is kept (`Verdict.Captcha`) and the walk goes on; a `log` bucket over its limit is appended to `Verdict.Exceeded`; a matching `final` stops after that bucket; a counter error returns at once (`Verdict.Err`) and wins over a kept captcha bucket. Each answering bucket (`ratelimit.AnsweringBucket`) carries its own `RetryAfter`.
_Avoid_: stopping on a captcha bucket, a captcha answer that beats a later ratelimit bucket

**Skipped bucket**:
A bucket the walk does not charge: a key part with no value, or a `captcha` bucket when `gateCleared` (the client holds this router's valid captcha gate). A skipped bucket is not charged, cannot answer, and its `final` does not apply.
_Avoid_: a cleared gate that only hides the captcha answer while still counting

**Counter key**:
`rl:<middleware name>:<bucket>:<first 16 hex of SHA-256 of the key part values joined by NUL>`; `windowcounter` appends `:<window start>`. Raw request values never reach Redis.
_Avoid_: the client IP as the Redis key, the ownership key, `rl:<bucket>` without the middleware name

**Step budget**:
`ratelimit.StepBudget` (250ms): one `context.WithTimeout` around the whole rate-limit step of a request, every bucket and every Redis command (dial and retries included). The Client's `simpleredis` `CommandTimeout` is the same value.
_Avoid_: a per-bucket timeout, a public timeout knob, decisionstore's 1s command timeout

## Overview

`pkg/ratelimit` owns the leg: authoring types (`BucketRule`, `KeyPart`), compile (`NewBucketSet`, used by `ValidateParams` and `Open`), evaluation (`(*BucketSet).Charge`), the `Counter` interface, and the Redis-backed `Client` (`Open`, `OwnershipKey`, `Settings`, `RedisSettings`, `Policy`, `Buckets()`, `Policy()`, `Incarnation()`). It does not import `pkg/configuration`; configuration imports it for `Config.RateLimitBuckets`, the way it imports `httprule.ActionRule`. The Bouncer step is `serveRateLimit` in `pkg/bouncer/bouncer_serve_ratelimit.go`, between `serveLAPI` and `serveAppSec`. Specs: `core_plugin_ratelimit_client`, `core_plugin_ratelimit_buckets`.

## How to use

- The leg is the last `publishedLeg` in `plugin.go` (`core_plugin_middleware_instance-slots.md`): `prepareRateLimit` fills an omitted `rateLimitInstanceName` with the Traefik name, resolves the password (`configuration.GetVariable(config, "RateLimitRedisPassword")`), and parses the sync rate (`configuration.RateLimitSyncRateDuration`, the parser `ValidateParams` also uses), only when owned; `rateLimitSettings` builds `ratelimit.Settings` for `open` and `ownershipKey`. Its claim runs last, so a taken name clears the other enabled legs. Without `rateLimitEnabled` the middleware reads no password file, dials nothing, and `ClearPublisher`s group `ratelimit`.
- A router subscribes when `bouncerEnabled` and `rateLimitInstanceName` are set (`Subscriptions.RateLimit`); `Watch` stores the Client through `route.ReceiveRateLimit`. An unpublished owner (typed nil) passes every request.
- Compile buckets once: `ValidateParams` compiles and discards (`RateLimitBuckets: bucket %d: …`) on the owner, `Open` compiles again in the reclaim create and keeps the set on the Client. Do not compile on the request path or per subscriber.
- In `serveRateLimit`: `loadedRateLimit()` and `usableCaptcha()` once per request; a request of the captcha page (`isCaptchaPageRequest`: the usable captcha's `IsCustomResourceRequest` or `HasChallengeMarker`) continues uncharged; `gateCleared` is `usableCaptcha().Check(req)`, computed only when `Buckets().HasCaptchaBucket()`; then `client.Buckets().Charge(ctx, client, b.name, req.Request, req.IPAddr(), gateCleared)` under `context.WithTimeout(req.Context(), ratelimit.StepBudget)`. `b.name` is the subscriber, so each subscriber keeps its own Redis keys. The client address is the `GetRemoteIP` result on `clientrequest.Request`; do not re-parse `RemoteAddr` or forwarded headers.
- Key part owners: `ip` → `ip.MaskPrefix` on that address (`ipv4Prefix` / `ipv6Prefix`, 0 keeps the whole address); `host` → `httprule.RequestHostname`; `path` → `req.URL.Path`; `method` → `req.Method`; `header` → `Header.Get`; `cookie` → `req.Cookie`; `query` → `URL.Query()` parsed at most once per `Charge`. A `pattern` keeps capture group 1. A part that is missing, empty, or does not match its pattern skips that bucket for the request, its `final` included.
- Read the `Verdict` with the Client's `Policy()`, in this order: `Exceeded` → INFO `crowdsec bouncer rate limit exceeded`; `Err` → `applyRateLimitFailureAction` with `policy.FailureAction` (`configuration.EffectiveRateLimitFailureAction` applied by the owner; empty and `passthrough` continue to AppSec; `ban` → ban page with header `ban:ratelimit-failure` and origin `lapi.OriginPluginRateLimitFailure`; `captcha` → `captchaRateLimitFailure`: a `bypassCaptcha` rule continues, no usable captcha → `ban:captcha-downgrade` through `logRateLimitCaptchaDowngrade`, else the challenge with `captcha:ratelimit-failure`); `RateLimit` → `answerRateLimit`: `handleBanStatusServeHTTP` with `policy.StatusCode`, `Retry-After` from that bucket's `RetryAfter` when `policy.ResponseHeaders`, header `ban:ratelimit:<bucket>`, origin `lapi.OriginPluginRateLimit(bucket)`, drop `ban`, and `warnCaptchaSuperseded`; `Captcha` → `answerCaptchaBucket`: a `bypassCaptcha` rule or no usable captcha → `answerRateLimit` for that bucket (the downgrade also through `logRateLimitCaptchaDowngrade`), else `handleCaptchaKindServeHTTP` with reason `ratelimit` and the bucket origin, so the header is `captcha:ratelimit:<bucket>` and the drop is `captcha`.
- Unit tests pass a fake `ratelimit.Counter` behind `ratelimit.NewTestClient(settings, counter)` (bound with `bindTestRateLimit` in `pkg/bouncer`), or a test type in `pkg/ratelimit`. Real Redis: `go test -tags realredis ./pkg/ratelimit` (`build_e2e_go-redis.md`).

## Pattern snippet

```go
client := b.loadedRateLimit()
if client == nil || match.SkipRateLimit {
	return false
}
captchaClient := b.usableCaptcha()
if isCaptchaPageRequest(captchaClient, req) {
	return false
}
buckets, policy := client.Buckets(), client.Policy()
gateCleared := captchaClient != nil && buckets.HasCaptchaBucket() && captchaClient.Check(req)
ctx, cancel := context.WithTimeout(req.Context(), ratelimit.StepBudget)
defer cancel()
verdict := buckets.Charge(ctx, client, b.name, req.Request, req.IPAddr(), gateCleared)
if verdict.Err != nil {
	return b.applyRateLimitFailureAction(rw, req, match, policy.FailureAction, captchaClient)
}
if verdict.RateLimit.Name != "" {
	b.answerRateLimit(rw, req, match, verdict.RateLimit, policy)
	return true
}
if verdict.Captcha.Name != "" {
	return b.answerCaptchaBucket(rw, req, match, verdict.Captcha, policy, captchaClient)
}
```

## Key files

- `pkg/ratelimit/`
- `pkg/bouncer/bouncer_serve_ratelimit.go`
- `pkg/bouncer/bouncer_leg_ratelimit.go` (`loadedRateLimit`, `ReceiveRateLimit`)
- `pkg/ratelimit/test_client.go` (`NewTestClient`)
- `pkg/configuration/configuration.go`
- `plugin.go`
- `vendor/github.com/david-garcia-garcia/traefik-middleware-utilities/windowcounter/limiter.go`

## Gotchas

- `windowcounter` at the `v1.0.10` pin is vendored as published. Do not patch `vendor/`; CI re-vendors. Exact mode is one EVAL (INCR, EXPIRE when the key has no TTL) plus one GET of the previous window per counted bucket; the buffered flush is one EVAL per batch of up to 256 keys.
- Buffered mode answers a Redis outage with a nil error and this replica's local count (utilities PR #62), skipping Redis for one sync rate after each failure. The failure action therefore only applies in exact mode or when the step deadline or request context ends. Tests that need a counter error against a dead address use `rateLimitSyncRate: 0`.
- A hit is counted even when it is answered, so a client that keeps sending stays limited.
- Every captcha answer of this leg is decided on the subscribing router at request time, from its own captcha subscription, not the owner's. There is no startup check for a `captcha` bucket or failure action `captcha`.
- A `captcha` bucket never passes a request: `bypassCaptcha` turns it into the `ratelimit` answer (429 by default), unlike every other captcha source, which `bypassCaptcha` lets through. The failure action `captcha` keeps the other sources' meaning and continues on `bypassCaptcha`.
- Captcha downgrade logging. The bind hook `logRateLimitCaptchaUnsubscribed` (on `ReceiveRateLimit`) logs ERROR `crowdsec bouncer rate limit captcha unavailable` with `reason` `unsubscribed`, `traefikName`, `instanceName` once per bind, when the policy has a `captcha` bucket or failure action `captcha` and the router has no captcha subscription. At request time a router subscribed to an unpublished or invalid captcha logs the same message with `reason` `unusable` (plus `captchaInstanceName`) through `logger.Debounced` (5s, keyed on the message process-wide). Every downgraded request logs DEBUG `rateLimitCaptchaDowngrade` (`ip`, `origin`, `reason`). Neither captcha answer of this leg reaches `handleCaptchaKindServeHTTP` without a usable captcha, so neither logs the per-request WARN `crowdsec bouncer captcha unsubscribed` the other legs keep.
- The captcha page's own requests (custom widget assets, any POST with the marker `crowdsec_captcha_challenge=v1`) skip every bucket only while the router has a usable captcha. A client that always posts the marker is never limited (`knowledge/debt/2026-11-21-rate-limit-captcha-marker-flood.md`). A custom template without the marker gets its verification POST counted.
- A solved client is exempt from `captcha` buckets for `captchaGracePeriodSeconds` (default 86400s). Only a `ratelimit` bucket on the same key bounds it; nothing enforces that one exists.
- The gate check (`captcha.Client.Check`, one HMAC) runs only on routers whose bound policy has a `captcha` bucket.
- Any owner edit of a Redis setting, a bucket row, or the policy opens a new Client (new incarnation); subscribers rebind on the next publish. Counters live in Redis by subscriber and bucket name, so an edit that keeps a bucket's name keeps its count in exact mode, and a rename starts it from zero. A rename of `rateLimitInstanceName` keeps the Client and moves the alias.
- A Client's lifecycle lines carry the `instanceName` it was created with; a rename that keeps the Client keeps that attr until the Client is reopened.
- Windows are whole seconds of at least 1s; `windowcounter` would only fail at `Take`, so `NewBucketSet` rejects them at startup.
- `Retry-After` is `windowcounter.Status.RetryAfter` (utilities v1.0.10+) rounded up to whole seconds, at least 1s, in `Charge`. It is the next admit with no other traffic; hits sent before it still count and push it out. `ratelimit.Status` aliases `windowcounter.Status` so `pkg/bouncer` (depguard) and test fakes do not import the vendored package.
- A `path`-matched bucket has the same alternate-encoding gap as ban and captcha rules (`knowledge/debt/2026-11-15-ban-captcha-path-rules-ambiguous-path-evasion.md`). A catch-all bucket does not, unless an earlier `final` bucket with a `path` condition matches the encoded path and stops the walk before it.
- Only the file provider is proven to decode the bucket list (real-stack `config/dynamic/rate-limit.yml`). Traefik drops unknown keys, which is why `algorithm`, `burst`, and `rateLimitStore` exist only to reject `tokenBucket`, a set burst, and `memory`.
- In exact mode a blackholed Redis costs every request up to `StepBudget` for the whole outage; there is no backoff gate (`knowledge/debt/2026-11-20-rate-limit-redis-backoff-gate.md`). Buffered mode only pays it on the requests that land when `windowcounter` retries Redis.
- `newClient` hands `simpleredis` a `debugCappedLogger`: the library logs WARN or ERROR per failed dial or command, so without the cap an outage writes WARN lines on every request. One failing request is one DEBUG line from `serveRateLimit`; keep a new Redis client of this leg behind the same cap.
