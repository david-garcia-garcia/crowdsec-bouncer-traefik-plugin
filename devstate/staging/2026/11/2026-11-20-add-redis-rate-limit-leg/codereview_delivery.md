# Delivery

## Motivation

The owner wants one middleware to be the whole edge WAF: LAPI decisions, AppSec, captcha, and ModSec are already legs of it, shared between routers under an instance name. A cap on how often a client calls a route is the missing piece. Today it has to come from Traefik's own `rateLimit` middleware, a second middleware on every router, which counts each middleware on one source (the client address, one header, or the host). It cannot say "5 POSTs a minute per IP on `^/login$`, 300 a minute per tenant taken from `^/t/([^/]+)/`, 1000 a minute per /24 as a dry run" in one place, and it reports nothing to CrowdSec.

The owner runs several application topologies with the same buckets. Without a shared policy, each router repeats the whole bucket list, Redis settings, status code, and failure behaviour, and an edit has to be made on every copy. Each application still needs its own budget: a client that uses up its limit on `api` must not lose its budget on `admin`.

One answer per limit is not enough either. A hard 429 on a soft limit blocks humans who browse fast. The owner wants a softer step first: over 300 requests a minute a client gets a captcha it can solve, and only over 1200 a minute does it get a 429. Requests from server-to-server API routes, which cannot solve a captcha, must still hit a limit.

Adding a fifth shared leg by hand would copy, once more, the per-leg wiring that LAPI, AppSec, captcha, and ModSec each repeat in `plugin.go` (prepare, open, claim with a hand-written rollback list, subscribe, Watch) and on `Bouncer` (bound value, received pointer, seen flag, instance name, receive trio). That debt was recorded with the instruction to propose a shared leg unit before the next leg.

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
- The captcha page's own requests (custom-provider widget assets, and form POSTs that carry the challenge marker) are never charged. On a router without AppSec, that form POST used to reach the application without anyone checking the answer, so the captcha could never be solved. When the policy can answer with a captcha, the router's captcha gate now validates the form itself: a right answer gets a 302 with the gate cookie, a wrong one gets the captcha page again with `captcha:ratelimit`.

The startup check for captcha readiness is gone, because the policy lives on the owner and the captcha on the subscriber. A new `bypassRateLimit` action-rule token skips only this leg.

Drops are recorded under `plugin:ratelimit:<bucket>` (`ban`, or `captcha` for the challenge page), under `plugin:ratelimit` for the gate answering a form, and under `plugin:ratelimit_failure` for the failure action.

Proof:

- Unit tests for each package.
- Yaegi tests for the rate-limit Client and the leg binding.
- `realredis` tests on Dragonfly for `pkg/ratelimit`, added to the Makefile target and CI.
- Real-stack Pester for:
  - single-middleware buckets (`rate_limit.Tests.ps1`)
  - one owner shared by two subscribers with separate budgets (`rate_limit_shared.Tests.ps1`)
  - captcha, solve, then hard 429 on stacked buckets, plus the router-without-captcha and `bypassCaptcha` cases (`rate_limit_captcha.Tests.ps1`)

## What this changes

**Operators.** New middleware settings turn on a Redis-backed rate limit and share it by instance name: `rateLimitEnabled`, `rateLimitInstanceName`, `rateLimitRedisHost`/`Password`/`PasswordFile`/`Database`, `rateLimitBuckets`, `rateLimitSyncRate`, `rateLimitFailureAction`, `rateLimitStatusCode`, `rateLimitResponseHeaders`, and `rateLimitStore`, plus a `bypassRateLimit` action-rule token; watch for the new verdict headers (`ban:ratelimit:<bucket>`, `captcha:ratelimit:<bucket>`, `*:ratelimit-failure`), the `plugin:ratelimit*` drop origins, INFO `crowdsec bouncer rate limit exceeded`, and ERROR `crowdsec bouncer rate limit captcha unavailable`.
**Admin users.** None.
**Developers.** `bouncer.New` now takes a `bouncer.Subscriptions` value instead of four subscription booleans, and a new published leg is one `publishedLeg` entry in `plugin.go` bound through `legBinding` (no generics, for Yaegi), not hand-written switches and fields.
**End users.** A client over a bucket's limit now gets HTTP 429 with `Retry-After` on the ban page, or the router's captcha page, which it can solve to keep going until a hard `ratelimit` bucket stops it.
