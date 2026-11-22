## Why

The owner runs several application topologies with one rate-limit policy and wants that policy configured once, the way LAPI, AppSec, captcha, and ModSec are already shared under an instance name. Round 1 shipped the rate-limit leg as an unpublished, per-middleware counter, and each new leg is still copied by hand into `plugin.go` and `Bouncer`. The owner also asked for a per-bucket answer: a hard `ratelimit` (the round-1 `deny`), a `captcha` that a client can solve, or `log`.

## What Changes

- **Leg descriptor (behaviour-preserving, first).** LAPI, AppSec, captcha, and ModSec move onto one descriptor table in `plugin.go` (prepare, open, ownership key, claim, Watch) and one binding type on `Bouncer`. Open order, claim rollback order, `ClearPublisher` on a dropped flag, and the `crowdsec bouncer bound|unbound` / `crowdsec instance name taken` lines stay as they are. `bouncer.New` takes one subscription value instead of four booleans.
- **Shared rate-limit leg.** `rateLimitEnabled` now means *own*: the middleware opens the rate-limit Client and publishes it under `rateLimitInstanceName` (reclaim group `ratelimit`, alias `alias:ratelimit:<name>`; an omitted name on an owner is the Traefik middleware name). A router with `bouncerEnabled` and `rateLimitInstanceName` subscribes and charges. The published Client carries the Redis counter, the compiled buckets, `rateLimitFailureAction`, `rateLimitStatusCode`, and `rateLimitResponseHeaders`; all of them are part of its ownership key. A subscriber reads no `rateLimit*` setting of its own.
- Counters stay per subscribing middleware: `rl:<subscriber middleware name>:<bucket>:<hash>`. A client that exhausts a bucket on one application still has its full budget on another that subscribes to the same policy.
- A subscriber whose owner is not published, or went away, charges nothing and passes the request on.
- A round-1 configuration (one middleware with `rateLimitEnabled`, `bouncerEnabled`, no instance name) keeps working: the owner subscribes to its own alias and keeps the same Redis keys.
- **Bucket actions.** `action` is `ratelimit` (default; was `deny`, renamed with no alias because `deny` was never released), `captcha`, or `log`.
  - `ratelimit`: unchanged answer (`rateLimitStatusCode`, `Retry-After`, `ban:ratelimit:<bucket>`).
  - `captcha`: the router's captcha challenge, remediation header `captcha:ratelimit:<bucket>`. A client holding a valid captcha gate (within `captchaGracePeriodSeconds`) is not counted by `captcha` buckets. On a request a `bypassCaptcha` rule matches, or on a router without a usable captcha, the bucket answers as `ratelimit`.
  - Verdict precedence over one walk: `ratelimit` > `captcha` > `log`. A `captcha` bucket over its limit does not stop the walk, so a stacked `ratelimit` bucket on the same key is still the hard ceiling.
  - The captcha page's own requests (custom-provider widget assets, posts carrying the challenge marker) are not charged to any bucket when the router has a usable captcha.
- **Validation.** `rateLimitFailureAction: captcha` no longer fails startup on a router without a captcha instance name: the policy lives on the owner, the captcha on the subscriber. A subscriber that binds a policy needing a captcha without a captcha subscription logs one ERROR; at request time the answer downgrades. A leftover `rateLimitInstanceName` with neither `bouncerEnabled` nor `rateLimitEnabled` fails startup, as for the other legs.
- **Limiter-level algorithm (addendum C).** New owner setting `rateLimitAlgorithm`: `slidingWindow` (default, the round-1 counter) or `tokenBucket` (one Redis token bucket per bucket: refill `requests / window`, new per-bucket `burst`, default `requests`, no queuing). It is part of the published policy and of the ownership key. The per-bucket `algorithm` key fails startup with a pointer to `rateLimitAlgorithm`; `burst` is valid only with `tokenBucket`; `rateLimitSyncRate` is read only by `slidingWindow`. Token-bucket keys end in `:tb`, so they never meet the sliding window's keys.
- **BREAKING against round 1 of this unmerged PR only** (nothing here is on `master`): `action: deny` now fails `ValidateParams` with an error that names the row.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_instance-slots`: five reclaim groups (adds `ratelimit`); lifecycle log contract adds `crowdsec ratelimit instance …`; new requirement "Rate limit publishes on reclaim group ratelimit" (owner, fill, ownership key, subscribe, rollback).
- `core_plugin_ratelimit_client`: the Client is opened on the owner with its policy and published (reverses "SHALL NOT be published"); counter keys use the subscribing middleware name; the failure action comes from the owner's policy and its `captcha` answer downgrades without a per-request WARN; the algorithm joins the ownership key, token-bucket keys end in `:tb`, the sync rate applies only to `slidingWindow`, and a token-bucket outage applies the failure action.
- `core_plugin_ratelimit_buckets`: `deny` → `ratelimit`; `captcha` action; walk precedence and the cleared-gate skip; the captcha page's own requests are not charged; validation accepts `ratelimit | captcha | log`; the owner's `rateLimitAlgorithm` (`slidingWindow` | `tokenBucket`), `burst`, and the per-bucket `algorithm` rejection.
- `core_plugin_middleware_bouncer`: five bound legs; a missing rate-limit Client passes through; remediation header table (`captcha:ratelimit:<bucket>`, `ratelimit` wording); `bypassCaptcha` and the unsubscribed-captcha WARN carve out the rate-limit leg; the rate-limit step runs on a subscribing router.
- `core_plugin_middleware_config-validation`: rate-limit settings are read on the owner only, the captcha check of the failure action is dropped, bucket `action` values, `rateLimitAlgorithm`, `burst`, and the row `algorithm` rejection; open-versus-subscribe adds the rate-limit leg.
- `core_plugin_lapi_usage-metrics`: captcha-bucket drops (`captcha` on the challenge, `ban` when answered as `ratelimit`).
- `build_e2e_pester_crowdsec-stack`: the rate-limit wording, plus real-stack cases for the shared leg, for captcha buckets, and for a `tokenBucket` owner (burst, refill, `Retry-After`).

## Impact

- `plugin.go` (descriptor table; rate-limit prepare, open, claim, Watch), `pkg/bouncer` (binding type, `Subscriptions`, `ReceiveRateLimit`, `serveRateLimit` reads the published Client, captcha-bucket answers, logging), `pkg/ratelimit` (`Client` carries buckets and policy, `OwnershipKey` covers them, `Incarnation()`, `Charge` takes the cleared-gate flag and returns the captcha bucket, `ratelimit` / `captcha` action constants), `pkg/configuration` (`RateLimitInstanceName`, validation moves, `RateLimitAlgorithm`). Addendum C: `pkg/ratelimit` counter contract (`Status`, `Limit`, sliding-window and token-bucket adapters), vendored `tokenbucket`, depguard allow-list.
- Tests: Go unit tests per package, a new test pinning bound/unbound traces and claim rollback order for every leg, the root Yaegi test, `pkg/yaegitest` program over the binding and descriptor, real-stack Pester for the shared leg and captcha buckets.
- Docs: `README.md` (connection table, rate-limit section, settings reference, header table, "Limits of this version"), devdocs `core_plugin_ratelimit.md`, `core_plugin_middleware_config-validation.md`, `core_plugin_middleware_instance-slots.md`, `build_e2e_real.md`.
- Follow-ups taken: `knowledge/debt/2026-11-20-extract-common-leg-abstraction.md`, `knowledge/debt/2026-11-20-rate-limit-captcha-action.md`. New follow-up: `knowledge/debt/2026-11-21-rate-limit-captcha-marker-flood.md`.
