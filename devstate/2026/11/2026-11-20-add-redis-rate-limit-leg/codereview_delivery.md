# Delivery

## Motivation

The owner wants one middleware to be the whole edge WAF: LAPI decisions, AppSec, captcha, and ModSec are already legs of it, shared between routers under an instance name. A cap on how often a client calls a route is the missing piece. Today it has to come from Traefik's own `rateLimit` middleware, a second middleware on every router, which counts each middleware on one source (the client address, one header, or the host). It cannot say "5 POSTs a minute per IP on `^/login$`, 300 a minute per tenant taken from `^/t/([^/]+)/`, 1000 a minute per /24 as a dry run" in one place, and it reports nothing to CrowdSec.

The owner runs several application topologies with the same buckets. Without a shared policy, each router repeats the whole bucket list, Redis settings, status code, and failure behaviour, and an edit has to be made on every copy. Each application still needs its own budget: a client that uses up its limit on `api` must not lose its budget on `admin`.

One answer per limit is not enough either. A hard 429 on a soft limit blocks humans who browse fast. The owner wants a softer step first: over 300 requests a minute a client gets a captcha it can solve, and only over 1200 a minute does it get a 429. Requests from server-to-server API routes, which cannot solve a captcha, must still hit a limit.

Adding a fifth shared leg by hand would copy, once more, the per-leg wiring that LAPI, AppSec, captcha, and ModSec each repeat in `plugin.go` (prepare, open, claim with a hand-written rollback list, subscribe, Watch) and on `Bouncer` (bound value, received pointer, seen flag, instance name, receive trio). That debt was recorded with the instruction to propose a shared leg unit before the next leg.

Counting itself needs a choice. A sliding window counts every hit, including the ones it refuses, so a client that keeps sending stays limited. Operators who think in Traefik's own terms want a token bucket instead: a burst allowance that refills at a steady rate, with refused hits not counted. The owner asked for that choice once for the whole limiter, not per bucket.

The counter library is in the pinned utilities module (v1.0.7) but not vendored there, and that tag still has the stale-previous-window and EXPIRE-not-retried defects, so the leg cannot be built on the current pin.

Priority: P2 — real operator pain (no distributed, multi-bucket rate limit or shared policy in the WAF middleware) with a workaround in Traefik's own `rateLimit` middleware.

## Implementation

The utilities module moves from v1.0.7 to v1.0.10, which vendors `windowcounter` (the Redis sliding-window counter, with the defects fixed and a `Retry-After` it computes itself). `backendbackoff` dropped the context from `Allow`, so the admission gate now checks `ctx.Err()` itself before calling it.

First, a refactor with no behaviour change. LAPI, AppSec, captcha, and ModSec move onto one `publishedLeg` table in `plugin.go`. Each entry holds plain values and funcs: group, enabled, instance name, prepare, open, ownership key, the empty value for `Watch`, receive, and subscribe. `New` loops over that table to prepare, open (`ClearPublisher` when the flag is off), claim, and subscribe. A failed claim clears every earlier enabled leg, the same lists as before. On `Bouncer`, one non-generic `legBinding` replaces the per-leg field groups. It keeps the last traced incarnation as a string, because Yaegi v0.16.1 cannot run generics or a binding with an `any` field. `bouncer.New` takes a `Subscriptions` value instead of four booleans. A new root test pins the `crowdsec bouncer bound|unbound` attributes and the claim rollback order for every leg. A Yaegi test runs the binding shapes.

The rate limit is the fifth entry. `rateLimitEnabled` now means *own*. The owner fills an omitted `rateLimitInstanceName` with its Traefik name. It opens a `ratelimit.Client` that holds the Redis counter, the compiled bucket set, and the policy (failure action, status code, `Retry-After` switch), and publishes it as `alias:ratelimit:<name>`. The ownership key hashes the Redis settings and the whole policy, so editing a bucket opens a new Client, while Redis counts of buckets that kept their names survive. A router with `bouncerEnabled` and the instance name subscribes. It reads no `rateLimit*` setting of its own. If the policy is not published, the router lets the request through.

`serveRateLimit` runs after the LAPI step and before AppSec. It loads the bound Client on each request and walks the buckets inside a 250ms budget, keyed `rl:<subscriber middleware name>:<bucket>:<hash>`, so each router keeps its own count. The bucket conditions reuse the `httprule` predicates of `bouncerActionRules`, set directly on the bucket row. Key parts come from IP or network prefix, header, cookie, query, host, path, or method, each with an optional capture pattern. The walk works like this:

- A `ratelimit` bucket over its limit answers at once: `rateLimitStatusCode`, `Retry-After`, `ban:ratelimit:<bucket>`.
- A `captcha` bucket over its limit is kept, and the walk goes on, so a `ratelimit` bucket stacked after it still wins.
- A `log` bucket over its limit only logs at INFO.
- A counter error applies the failure action. With the default buffered sync, this happens only after the step budget runs out.

The captcha pieces are decided on the subscribing router:

- A client holding a valid gate is not counted by `captcha` buckets.
- When a `bypassCaptcha` rule matches, or the router has no usable captcha, a `captcha` bucket gives its `ratelimit` answer. An ERROR is logged once per bind when the router has no captcha subscription, and debounced to once every 5s when its captcha is unusable. Every such request also logs at DEBUG.
- Custom-provider widget assets of a usable captcha are never charged.
- A form POST that carries the challenge marker skips the buckets only when this router's captcha gate answers it for the rate limit: a usable captcha, a policy that can answer with a captcha, and no `bypassCaptcha` rule. The gate then validates the form itself, so the captcha can be solved on a router without AppSec: a right answer gets a 302 with the gate cookie, a wrong one gets the captcha page again with `captcha:ratelimit`. Any other marker POST is charged like any request, so adding the marker to `POST /login` does not turn a brute-force bucket off. The cheap checks run before the body is read, so routes whose policy has no captcha answer never peek a POST body for the marker.

A subscriber whose owner stops being published passes every request uncharged, so that state is logged: WARN `crowdsec bouncer rate limit owner unavailable` once when the router loses its owner, and INFO `crowdsec bouncer rate limit owner available` when it binds one again. The pending WARN is kept per router name for the whole process, not per `Bouncer`, because a Traefik reload rebuilds every middleware in an order it does not fix; without that, a subscriber rebuilt after the returning owner never logged the INFO for its WARN. Nothing is logged per request.

The owner picks the counting algorithm for every bucket with `rateLimitAlgorithm`: `slidingWindow` (default, the counter above) or `tokenBucket` (one Redis token bucket per bucket, refilled at `requests` per `window`, up to the bucket's `burst`, default `requests`, with no queuing). Both sit behind one plugin-owned counter contract (`Status{Allowed, RetryAfter}`), so the walk, the answers, and `Retry-After` rounding do not branch on the algorithm. The algorithm is part of the published policy and its ownership key. Token-bucket keys end in `:tb`, so a switch starts every bucket from zero and never meets the other algorithm's keys. `burst` on a `slidingWindow` policy, or an `algorithm` key on a bucket row, fails startup with an error that names `rateLimitAlgorithm`. The token bucket has no buffered mode: every counted bucket is one EVAL, and a Redis error applies the failure action whatever `rateLimitSyncRate` says.

The startup check for captcha readiness is gone, because the policy lives on the owner and the captcha on the subscriber. A new `bypassRateLimit` action-rule token skips only this leg.

Drops are recorded under `plugin:ratelimit:<bucket>` (`ban`, or `captcha` for the challenge page), under `plugin:ratelimit` for the gate answering a form, and under `plugin:ratelimit_failure` for the failure action.

Proof:

- Unit tests for each package.
- Yaegi tests for the rate-limit Client (both algorithms) and the leg binding.
- `realredis` tests on Dragonfly for `pkg/ratelimit` (sliding window and token bucket), added to the Makefile target and CI.
- Real-stack Pester for:
  - single-middleware buckets, a `tokenBucket` owner (burst, `Retry-After`, refill), and a bucket row with `algorithm` that fails startup (`rate_limit.Tests.ps1`)
  - one owner shared by two subscribers with separate budgets, plus owner removal and return with one WARN and one INFO per subscriber (`rate_limit_shared.Tests.ps1`)
  - captcha, solve, then hard 429 on stacked buckets, plus the router-without-captcha and `bypassCaptcha` cases (`rate_limit_captcha.Tests.ps1`)

## What this changes

**Operators.** New middleware settings turn on a Redis-backed rate limit and share it by instance name: `rateLimitEnabled`, `rateLimitInstanceName`, `rateLimitAlgorithm` (`slidingWindow` | `tokenBucket`), `rateLimitRedisHost`/`Password`/`PasswordFile`/`Database`, `rateLimitBuckets` (with a per-bucket `burst` for the token bucket), `rateLimitSyncRate`, `rateLimitFailureAction`, `rateLimitStatusCode`, `rateLimitResponseHeaders`, and `rateLimitStore`, plus a `bypassRateLimit` action-rule token; watch for the new verdict headers (`ban:ratelimit:<bucket>`, `captcha:ratelimit:<bucket>`, `*:ratelimit-failure`), the `plugin:ratelimit*` drop origins, INFO `crowdsec bouncer rate limit exceeded`, WARN `crowdsec bouncer rate limit owner unavailable` and its INFO `crowdsec bouncer rate limit owner available`, and ERROR `crowdsec bouncer rate limit captcha unavailable`.
**Admin users.** None.
**Developers.** `bouncer.New` now takes a `bouncer.Subscriptions` value instead of four subscription booleans, and a new published leg is one `publishedLeg` entry in `plugin.go` bound through `legBinding` (no generics, for Yaegi), not hand-written switches and fields.
**End users.** A client over a bucket's limit now gets HTTP 429 with `Retry-After` on the ban page, or the router's captcha page, which it can solve to keep going until a hard `ratelimit` bucket stops it.
