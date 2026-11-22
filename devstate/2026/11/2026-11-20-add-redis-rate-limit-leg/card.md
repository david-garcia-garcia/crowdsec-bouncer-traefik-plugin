## Motivation
The owner wants one middleware to be the whole edge WAF: LAPI decisions, AppSec, captcha, and ModSec are already legs of it, shared between routers under an instance name. A cap on how often a client calls a route is the missing piece. Today it has to come from Traefik's own `rateLimit` middleware, a second middleware on every router, which counts each middleware on one source (the client address, one header, or the host). It cannot say "5 POSTs a minute per IP on `^/login$`, 300 a minute per tenant taken from `^/t/([^/]+)/`, 1000 a minute per /24 as a dry run" in one place, and it reports nothing to CrowdSec.

The owner runs several application topologies with the same buckets. Without a shared policy, each router repeats the whole bucket list, Redis settings, status code, and failure behaviour, and an edit has to be made on every copy. Each application still needs its own budget: a client that uses up its limit on `api` must not lose its budget on `admin`.

One answer per limit is not enough either. A hard 429 on a soft limit blocks humans who browse fast. The owner wants a softer step first: over 300 requests a minute a client gets a captcha it can solve, and only over 1200 a minute does it get a 429. Requests from server-to-server API routes, which cannot solve a captcha, must still hit a limit.

Adding a fifth shared leg by hand would copy, once more, the per-leg wiring that LAPI, AppSec, captcha, and ModSec each repeat in `plugin.go` (prepare, open, claim with a hand-written rollback list, subscribe, Watch) and on `Bouncer` (bound value, received pointer, seen flag, instance name, receive trio). That debt was recorded with the instruction to propose a shared leg unit before the next leg.

Counting itself needs a choice. A sliding window counts every hit, including the ones it refuses, so a client that keeps sending stays limited. Operators who think in Traefik's own terms want a token bucket instead: a burst allowance that refills at a steady rate, with refused hits not counted. The owner asked for that choice once for the whole limiter, not per bucket.

The counter library is in the pinned utilities module (v1.0.7) but not vendored there, and that tag still has the stale-previous-window and EXPIRE-not-retried defects, so the leg cannot be built on the current pin.

Priority: P2 — real operator pain (no distributed, multi-bucket rate limit or shared policy in the WAF middleware) with a workaround in Traefik's own `rateLimit` middleware.

## Implementation
The utilities module moves from v1.0.7 to v1.0.12. That vendors `windowcounter` (the Redis sliding-window counter, with the defects fixed and a `Retry-After` it computes itself) and `tokenbucket`, which since v1.0.11 reads its Redis fields by name and raises a short idle TTL to the refill time. `backendbackoff` dropped the context from `Allow` (v1.0.9), so the admission gate checks `ctx.Err()` itself before calling it. Since v1.0.12 `Allow` returns a `Permit` that `Report` takes, and a report whose generation no longer matches is ignored. The AppSec and ModSec gate keeps the `Permit` on its ticket and logs its "backoff ended" line only when the probe's report is applied, so a probe whose lease expired cannot end the backoff while the current probe is in flight.

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

## Merge readiness
Ready for review once Main Process is green on d4585c4e. 6 follow-up items remain as debt notes; none blocks the merge.

Priority: P2 — real operator pain (no distributed, multi-bucket rate limit or shared policy in the WAF middleware) with a workaround in Traefik's own `rateLimit` middleware.
Reviewed head: d4585c4e
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 5/6 | Ready once the Main Process rerun is green |
| CI proof | 5/6 | 7/8 on d4585c4e; Main Process failed and did not reproduce locally https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/45041772455 |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-11-20-add-redis-rate-limit-leg pushed | `git` |
| OpenSpec | share-rate-limit-leg-and-bucket-actions | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/228 | pr-host |
| CI | build d4585c4e: 7/8 check runs succeeded (Race detector and 6 e2e jobs, https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/45041772458); Main Process failed in its `go test -v -cover ./...` step (https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/45041772455). The same tests pass on Linux Go 1.22 from a clean `git archive` and on Windows; rerun pending. Previous head 2147e0f4 was 8/8. | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/45041772455 |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [build_e2e_pester_crowdsec-stack](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/openspec/changes/archive/2026-11-21-add-redis-rate-limit-leg/proposal.md) — modified
- [build_e2e_pester_crowdsec-stack](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/openspec/changes/archive/2026-11-22-share-rate-limit-leg-and-bucket-actions/proposal.md) — modified
- [core_plugin_lapi_usage-metrics](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/openspec/changes/archive/2026-11-21-add-redis-rate-limit-leg/proposal.md) — modified
- [core_plugin_lapi_usage-metrics](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/openspec/changes/archive/2026-11-22-share-rate-limit-leg-and-bucket-actions/proposal.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/openspec/changes/archive/2026-11-21-add-redis-rate-limit-leg/proposal.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/openspec/changes/archive/2026-11-22-share-rate-limit-leg-and-bucket-actions/proposal.md) — modified
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/openspec/changes/archive/2026-11-21-add-redis-rate-limit-leg/proposal.md) — modified
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/openspec/changes/archive/2026-11-22-share-rate-limit-leg-and-bucket-actions/proposal.md) — modified
- [core_plugin_middleware_instance-slots](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/openspec/changes/archive/2026-11-22-share-rate-limit-leg-and-bucket-actions/proposal.md) — modified
- [core_plugin_ratelimit_buckets](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/openspec/changes/archive/2026-11-21-add-redis-rate-limit-leg/proposal.md) — added
- [core_plugin_ratelimit_buckets](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/openspec/changes/archive/2026-11-22-share-rate-limit-leg-and-bucket-actions/proposal.md) — added
- [core_plugin_ratelimit_client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/openspec/changes/archive/2026-11-21-add-redis-rate-limit-leg/proposal.md) — added
- [core_plugin_ratelimit_client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/openspec/changes/archive/2026-11-22-share-rate-limit-leg-and-bucket-actions/proposal.md) — added

Completed:
- [build_e2e_pester_crowdsec-stack](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/openspec/specs/build_e2e_pester_crowdsec-stack/spec.md) — modified
- [core_plugin_lapi_usage-metrics](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/openspec/specs/core_plugin_lapi_usage-metrics/spec.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/openspec/specs/core_plugin_middleware_bouncer/spec.md) — modified
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/openspec/specs/core_plugin_middleware_config-validation/spec.md) — modified
- [core_plugin_middleware_instance-slots](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/openspec/specs/core_plugin_middleware_instance-slots/spec.md) — modified
- [core_plugin_ratelimit_buckets](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/openspec/specs/core_plugin_ratelimit_buckets/spec.md) — added
- [core_plugin_ratelimit_client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/openspec/specs/core_plugin_ratelimit_client/spec.md) — added


## Deviations from the ask
- taken: each bucket carries `match: {method, path, host, headers, cookies}`. → the same `httprule.Rule` predicates are squashed onto the bucket row (`name`, `path`, `host`, …, `key`, `requests`, `window`, `action`), exactly as a `bouncerActionRules` row carries them. `match` and `key` stay separate concepts; only the nesting goes. — `pkg/httprule/action.go (ActionRule embeds Rule with mapstructure:",squash")` — one authoring shape for "which requests" across the plugin, and one less nesting level in Traefik plugin config, where only list → object → list depth is proven by the existing e2e.. Requester: not asked.


## Follow-up issues
- [ ] [Send `RateLimit-*` headers on rate-limit responses](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/knowledge/debt/2026-11-20-rate-limit-ratelimit-response-headers.md) — the requirement lists `RateLimit-*` headers beside `Retry-After`; the IETF draft's header shape is unsettled, so this change sends `Retry-After` only (since utilities v1.0.10 the counter does return Limit, Remaining and Reset).
- [ ] [Skip Redis for a while after rate-limit counter failures](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/knowledge/debt/2026-11-20-rate-limit-redis-backoff-gate.md) — in exact mode (`rateLimitSyncRate: 0`) a blackholed Redis costs each request the full 250ms rate-limit budget for the whole outage; no gate skips Redis after repeated failures. Buffered mode skips Redis for one sync rate after a failure (utilities v1.0.9).
- [ ] [Name `bypassRateLimit` in the single-reading path requirement](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/knowledge/debt/2026-11-21-single-reading-path-spec-names-bypassratelimit.md) — the live "Action-rule skips need a single-reading path" requirement omits `bypassRateLimit`, though the code and "Action rules fold every matching row" drop it on an ambiguous path too.
- [ ] [Bound the rate-limit exemption for captcha-page traffic](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/knowledge/debt/2026-11-21-rate-limit-captcha-marker-flood.md) — widget assets of a usable captcha, and a marker POST that this router's captcha gate answers, skip every rate-limit bucket (human decision 5), so a scripted client can keep posting the marker uncharged and each such POST costs a siteverify call.
- [ ] [Align the instance-slots "Replace A by B" trace scenario with the code](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/knowledge/debt/2026-11-21-instance-slots-replace-trace-scenario.md) — the live instance-slots scenario "Replace A by B logs two bound lines" says no unbound line between them; the code logs unbound for A first, and the leg extraction pins the code.
- [ ] [Add the in-memory rate-limit store (`rateLimitStore: memory`)](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/knowledge/debt/2026-11-22-rate-limit-memory-store.md) — only the `redis` store ships; `rateLimitStore: memory` fails startup, so single-replica operators without Redis cannot use the rate limiter. A memory store counts per replica, and `windowcounter` has no in-memory variant.


## How this fits together
Ticket 2026-11-20-add-redis-rate-limit-leg on branch 2026-11-20-add-redis-rate-limit-leg targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/228; CI build d4585c4e: 7/8 check runs succeeded (Race detector and 6 e2e jobs, https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/45041772458); Main Process failed in its `go test -v -cover ./...` step (https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/45041772455). The same tests pass on Linux Go 1.22 from a clean `git archive` and on Windows; rerun pending. Previous head 2147e0f4 was 8/8.

## Explore Decisions
None.

## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/devstate/2026/11/2026-11-20-add-redis-rate-limit-leg/codereview_standards.md) — 5 total, 0 pending, 3 completed, 2 skipped
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/devstate/2026/11/2026-11-20-add-redis-rate-limit-leg/codereview_nitpicks.md) — 5 total, 0 pending, 5 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/devstate/2026/11/2026-11-20-add-redis-rate-limit-leg/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/devstate/2026/11/2026-11-20-add-redis-rate-limit-leg/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/devstate/2026/11/2026-11-20-add-redis-rate-limit-leg/codereview_security.md) — 2 total, 0 pending, 2 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/devstate/2026/11/2026-11-20-add-redis-rate-limit-leg/codereview_performance.md) — 1 total, 0 pending, 1 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/devstate/2026/11/2026-11-20-add-redis-rate-limit-leg/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-20-add-redis-rate-limit-leg/devstate/2026/11/2026-11-20-add-redis-rate-limit-leg/codereview_coverage.md) — 2 total, 0 pending, 2 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 6 added / 14 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | d4585c4e43997f3b68f57215676977dc45a1b583 | Card must match the branch you measured |

### Stored data model
- **New store**: Redis/Dragonfly, the rate-limit Redis named by the owner's `rateLimitRedisHost`, `rateLimitRedisDatabase`, `rateLimitRedisPassword`/`File` (a separate client from the decision-cache Redis, `pkg/ratelimit/client.go:131,145`). New key family: sliding-window hit counters.
  - Key: `rl:<subscriber traefik name>:<bucket name>:<hash16>:<windowStartUnix>`. `rl:` + the charging router's name + the owner's bucket name + the first 16 hex characters of SHA-256 over the key-part values joined by NUL (`pkg/ratelimit/key.go:17,112`); the counter appends the window start (`windowcounter/limiter.go:643`). The name segment is the subscribing router (`b.name`, `pkg/bouncer/bouncer_serve_ratelimit.go:63`), not the owner's `rateLimitInstanceName`, so every subscriber of one shared owner keeps its own counters under the owner's bucket names. Bucket names cannot contain `:`. Raw key-part values (IP, header, cookie, query, host, path, method) are never written, only the hash.
  - Fields: one integer per key, the hit count of that window, stored as a decimal string by `INCR`/`INCRBY` and read back with `GET` + `strconv.ParseInt` (a miss reads as 0) (`limiter.go:377,390`).
  - TTL: `2 x window` (`limiter.go:145`). `syncRate=0` (exact): one EVAL of `INCR` then `EXPIRE` when the key has no TTL (`limiter.go:44`). `syncRate>0` (buffered): one EVAL per up to 256 keys of `INCRBY delta` then `EXPIREAT windowStart+2*window` only when the key did not exist (`limiter.go:30`).
  - Writers: `BucketSet.Charge` → `Client.Take` → `Limiter.Take`, once per matching bucket with a key value per request; buffered deltas also flush on the timer, `Sleep`, and `Close`. Readers: the same limiter only (`GET` on the current and previous window keys). No other component reads `rl:*`.
  - migration: not applicable. Redis is schemaless; keys are created by the shipped code's own first `INCR`/`EVAL` and expire on their own. Nothing to deploy.
  - Rollback: `master` (v1.9.7) neither reads nor writes `rl:*`. Leftover keys expire by their TTL (at most about 3 windows after the window start). No red flag.
- **New store**: Redis/Dragonfly, the same rate-limit Redis, when the owner sets `rateLimitAlgorithm: tokenBucket`. New key family: token buckets.
  - Key: `rl:<subscriber traefik name>:<bucket name>:<hash16>:tb`, the same plugin key as the sliding window plus the suffix `:tb` (`pkg/ratelimit/token_bucket_counter.go:16,49`), so the two key families never meet and a switch of algorithm starts from zero.
  - Fields: one Redis hash per key with `last` (time of the last take) and `tokens` (tokens left), written by `HSET` in the vendored Lua script (`tokenbucket/lua.go:54`); an empty hash reads as a full bucket (`tokens = burst`).
  - TTL: one full refill (`burst x window / requests`) rounded up to whole seconds, at least 1s, set by `EXPIRE` on every take (`token_bucket_counter.go:70`, `lua.go:55`).
  - Writers and readers: `BucketSet.Charge` → `tokenBucketCounter.Take` → `tokenbucket.Redis.Allow`, one EVAL per counted bucket per request. No other component reads these keys.
  - migration: not applicable; schemaless, created and expired by the script. Rollback: `master` neither reads nor writes them; they expire by their TTL. No red flag.
- **Fields**: Redis/Dragonfly, rate-limit window counters: key and value unchanged by round 2. The `windowcounter` v1.0.9/v1.0.10 bump replaces round 1's `INCR` + separate `EXPIRE` with one EVAL script and the one-key flush script with a batched one; key format `{opaqueKey}:{windowStart}`, the integer value, and the `2 x window` TTL are the same, and the plugin key keeps `b.name` as in round 1. Not a delta against `master`, which has no such store.
- Redis/Dragonfly, LAPI decision store (`pkg/decisionstore/redis.go`, not in the pin): no key or value change. The vendored `simpleredis` bump changes transport only (pool turns, RESP parsing, TLS/user config), not what is written.
- Not persistent, so not listed as stores: the reclaim-table key `ratelimit:owner:<fnv64>` (process memory; with round 2 it excludes the instance name), the buffered `windows` map, and the new usage-metrics origin label values under `plugin:ratelimit` on the existing LAPI metrics push.
