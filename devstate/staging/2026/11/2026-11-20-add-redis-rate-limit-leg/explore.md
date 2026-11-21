# Explore

## Concepts

Units this change touches (worktree @ `53950dcb`, dest `master`):

- `plugin.go` — `New`, `openOwned` / `openOwnedLeg`: constructor that Opens reclaim-held legs on `bindCtx`. The rate limiter is a new Open-only leg (no alias, no Watch).
- `pkg/bouncer/bouncer.go` — `Bouncer`, `ServeHTTP`: per-router handler; pipeline is trusted skip → `foldActionRules` (ban early return) → `serveLAPI` → `serveAppSec` → `next`.
- `pkg/bouncer/bouncer_serve_remediation.go` — `handleBanStatusServeHTTP` (ban template with an explicit status; AppSec already serves 429 through it), `recordDropped` (usage metrics, only when a LAPI client is bound).
- `pkg/bouncer/remediation_header.go` — closed `kind:reason[:origin]` verdict header; third field only for reason `lapi` today.
- `pkg/bouncer/bouncer_serve_captcha.go` — `handleCaptchaKindServeHTTP`; a valid gate cookie lets the request through (why the bucket `captcha` action is deferred).
- `pkg/httprule/action.go` — action tokens, `ActionMatch`, `Fold`; `bypassRateLimit` joins `bypassLapi` / `bypassAppsec` and the ambiguous-path skip guard.
- `pkg/httprule/set.go` — `Rule` predicates (RE2, AND), `requestHostname` (host owner) — reused for bucket matching.
- `pkg/configuration/configuration.go` — `Config` (alphabetical json tags), `ValidateParams`, `validateFailureAction`, `FailureAction*`, `Reason*`.
- `pkg/ip` — client address owner (`GetRemoteIP`); no prefix-mask helper exists (new, additive).
- `pkg/reclaim/default.go` — `OpenWithHooks` (holder + Sleep/Wake/Close hooks).
- `pkg/lapi/client_metrics.go` — `OriginPlugin*` usage-metrics origins (`plugin:rules:<name>` precedent).
- `pkg/yaegitest/interpreter.go` — yaegi v0.16.1 harness over this module + vendored utilities.
- Vendored utilities `v1.0.7`: `iplookup`, `reclaim`, `simpleredis`, `traefikemulator`. `windowcounter` must be added to `vendor/` (same tag, no bump).
- New: a rate-limit package (Limiter holder + bucket compile/evaluate) — name chosen at propose.

How they connect:

```
ServeHTTP
  ├─ enabled? ─ no → next
  ├─ GetRemoteIP → clientrequest.Request (IP owner)
  ├─ trusted client ─────────────────────────────→ next   (skips rate limit too)
  ├─ foldActionRules ─ ban ──────────────────────→ ban:rules
  ├─ serveLAPI ── ban / captcha decision ────────→ written (no bucket charged)
  ├─ ► serveRateLimit (new) ◄ skipped by bypassRateLimit
  │     buckets in order: match(Rule) → key parts → windowcounter.Take
  │       over limit + deny → handleBanStatusServeHTTP(429) + Retry-After,
  │                            header ban:ratelimit:<bucket>, origin plugin:ratelimit:<bucket>
  │       over limit + log  → log, continue
  │       Take error        → rateLimitFailureAction (passthrough|ban|captcha)
  ├─ serveAppSec ── captcha rule / AppSec query ─→ written
  └─ next

plugin.New ── reclaim.OpenWithHooks(key = middleware + redis + syncRate)
                 create: simpleredis.New + windowcounter.New
                 hooks:  Limiter.Sleep / Wake / Close (+ simpleredis Close)
              └─ bouncer.New(..., limiter, buckets)   (no alias, no Watch)
```

Call sites that matter (roots searched: `pkg/`, `plugin.go`, non-test `.go`):

- `ActionSet.Fold`: 1 caller (`pkg/bouncer/bouncer.go:196`).
- `formatRemediationHeader`: 4 callers (`bouncer_serve_captcha.go:95`, `remediation_header.go:53,89,91`).
- `handleBanStatusServeHTTP`: 2 callers (`bouncer_serve_appsec_verdict.go:24`, `bouncer_serve_remediation.go:32`).
- `recordDropped`: 4 callers in `pkg/bouncer`.
- `bouncerActionRules` authoring shape in e2e: `tests/e2e/real/config/dynamic/action-rules.yml`, `bypass-captcha.yml`, `captcha-appsec.yml`, mock `request-bypass-rules`, `captcha-ban-origins` (file provider only).

Reproduce:

- Rate-limit leg: `not found` (new capability; nothing to reproduce).
- Utilities `BUGS.md` claims, measured on a `git archive v1.0.7` copy (local clone master `ba52347` is an ancestor of `v1.0.7` with no `tokenbucket/` / `windowcounter/` diff): `go test -short -run TestRepro_ ./windowcounter ./tokenbucket` → all pass (11 tests; 1 skip). Branch-only repros from open upstream PRs run against v1.0.7 code: tokenbucket #54 tests **fail** (4 tests); windowcounter #63 `TestRepro_BufferedStalePreviousAtBoundary` **fails**. Plugin-shaped probe (tokenbucket Memory, maxDelay 0, hits 0–2µs apart): rate 50 → 188 admitted vs 149 correct; rate 1000 → 3029 vs 1999.
- Yaegi: upstream `TestYaegi_*` for both packages pass at v1.0.7 (yaegi v0.16.1; live Redis variants skipped). `yaegi` binary is on PATH on this machine.

Outside facts used:

- `knowledge/research/ext_traefik-middleware-utilities_windowcounter/` (created this run).
- `knowledge/research/ext_traefik-middleware-utilities_tokenbucket/` (created this run).
- `knowledge/research/ext_traefik_plugins_config-decode/` (mapstructure `WeaklyTypedInput`, `StringToSliceHookFunc`, field-name match).
- `knowledge/research/ext_crowdsec_appsec_rate-limit/` (AppSec already answers 429 as `ban:appsec`).
- In-tree: `README.md` verdict-header table and trusted-IP text; `knowledge/devdocs/core_plugin_middleware.md`, `core_plugin_lapi_usage-metrics.md`.

## Decisions

Chosen:

- Leg shape: an Open-only leg. `reclaim.OpenWithHooks` holds one `windowcounter.Limiter` + its `simpleredis` client per (middleware name, `rateLimitRedis*`, `rateLimitSyncRate`); hooks are the Limiter's `Sleep` / `Wake` / `Close` plus closing the Redis client (`Limiter.Close` does not close the injected client). Buckets compile once in `bouncer.New` and stay on `Bouncer`, like action rules.
- Algorithm and store: `windowcounter` (sliding window) on Redis only, vendored at the pinned `v1.0.7` — no module bump (v1.0.8 has no fix for either package).
- Pipeline seam: a `serveRateLimit` step between `serveLAPI` and `serveAppSec` in `ServeHTTP`. Trusted clients, action-rule bans, and LAPI ban/captcha answers come first and are not charged; the captcha rule and AppSec come after, so a flood never reaches AppSec.
- Deny response: `handleBanStatusServeHTTP` with `rateLimitStatusCode` (default 429) — the ban template, as AppSec's 429 already uses — plus `Retry-After`. `bouncerRemediationStatusCode` is untouched.
- Verdict header `ban:ratelimit:<bucket>` (third field generalised from "reason `lapi`" to "reason `lapi` or `ratelimit`"); failure `ban|captcha:ratelimit-failure` (`deviations.md`).
- Metrics: `recordDropped` with origin `plugin:ratelimit:<bucket>` (new `OriginPluginRateLimit` helper beside `OriginPluginRules`), remediation `ban`.
- Exemption: new action token `bypassRateLimit`; `Fold` gains `SkipRateLimit` under the same ambiguous-path guard as the other skips.
- Failure action: `rateLimitFailureAction` reuses `passthrough | ban | captcha` and `validateFailureAction`; default `passthrough` (`deviations.md`).
- Bucket authoring: flat `httprule.Rule` predicates on the bucket row (squash, like `ActionRule`), plus `key`, `requests`, `window`, `action`, `final` (`deviations.md`).
- Validation in `ValidateParams`: window ≥ 1s and whole seconds (windowcounter only errors at `Take`), `requests` ≥ 1, unique non-empty colon-free bucket names, known `from` sources, RE2 compile of predicates and key patterns, Redis password file read only when the leg is on (mirrors `lapiRedis*`).
- First slice (this PR): `slidingWindow` on Redis; actions `deny` and `log`; `bypassRateLimit`; `Retry-After`. Deferred with debt notes: `tokenBucket` / `burst` / memory store (upstream blocker), bucket `captcha` action, `RateLimit-*` headers.
- Common leg abstraction: suggested, not taken in this PR (`knowledge/debt/2026-11-20-extract-common-leg-abstraction.md`).
- Yaegi: implement adds a `pkg/yaegitest` program that imports the rate-limit path through vendored `windowcounter`.

Rejected:

- Bump utilities to `v1.0.8` — no rate-limit fix in it; `backendbackoff.Allow` signature change is unrelated churn.
- Pin a pseudo-version of an unmerged upstream fix branch — not a release; none of those branches contains `v1.0.7`.
- Patch `vendor/` — CI re-vendors; forbidden by the workflow.
- Ship `tokenBucket` on v1.0.7 — measured over-admission under flood; no correction possible on the published surface.
- A new header kind `ratelimit` — breaks the documented closed kind set.
- Reusing `bouncerRemediationStatusCode` for rate-limit denies — the ask is a separate 429; AppSec already carries its own status the same way.
- Placing the rate limit before LAPI — would charge clients LAPI already bans and give them a 429 instead of the ban page.
- Publishing the limiter as an instance (`*InstanceName` alias) — requirement Out of scope.
- Extracting the leg abstraction now — refactor of three shipped legs with no rate-limit criterion behind it.

Live contract: `core_plugin_middleware_bouncer` (pipeline, action tokens, verdict header), `core_plugin_middleware_config-validation` (new keys), `core_plugin_lapi_usage-metrics` (new plugin origin). New leaf for the rate-limit leg itself — named at propose.

## Open questions

- Q: Does the existing `bypass` action also skip the rate limit?
  Rank: additive asked — new `bypassRateLimit` token and `SkipRateLimit` field in `pkg/httprule/action.go`; requirement semantics 5 and open decision 1
  Decision: assumed — no. Only `bypassRateLimit` skips the rate limit; `bypass` keeps meaning "skip LAPI and AppSec". The `Fold` skip guard change has 1 caller (`pkg/bouncer/bouncer.go:196`).
  By: explore
- Q: Should buckets support `action: captcha` in this PR?
  Rank: additive asked — new action value on a unit this change creates; requirement open decision 2
  Decision: assumed — no. Ship `deny` and `log`; `action: captcha` fails `ValidateParams` with a not-supported-in-this-version error instead of being accepted. `handleCaptchaKindServeHTTP` lets a solved gate cookie through, so a captcha bucket would stop limiting every solved client; that exemption is the unanswered decision. Follow-up: `knowledge/debt/2026-11-20-rate-limit-captcha-action.md`.
  By: propose
- Q: What does the leg do when Redis is unreachable?
  Rank: additive asked — new per-router setting; requirement open decision 3
  Decision: assumed — `rateLimitFailureAction` default `passthrough` (fail open), also accepting `ban` and `captcha` via the existing validator (`deviations.md`). Applied whenever `Take` returns an error, including buffered mode's retained flush error; the first error stops the bucket walk and the local verdict that came with it is ignored. A failure-action captcha honours `bypassCaptcha`, as the LAPI and AppSec failure captchas do (design decision 11).
  By: propose
- Q: Do empty `rateLimitRedis*` settings default to `lapiRedis*`?
  Rank: additive asked — new config keys; requirement open decision 4
  Decision: assumed — no. Separate, explicit settings mirroring `lapiRedisHost/Password/PasswordFile/Database` (no read hosts: windowcounter writes on every path).
  By: explore
- Q: How are key values stored in Redis?
  Rank: additive asked — key format of a unit this change creates; requirement open decision 5
  Decision: assumed — hashed: `<prefix>:<middleware name>:<bucket>:<sha256 hex prefix of the joined key parts>`, windowcounter appends `:<window start>`. The middleware name keeps two middlewares with the same bucket name apart while replicas of one middleware still share.
  By: explore
- Q: Is there an in-memory store for single-replica users?
  Rank: additive asked — `rateLimitStore` value; requirement open decision 6
  Decision: assumed — not in this PR. `rateLimitStore` ships with the single accepted value `redis` (default); `memory` fails `ValidateParams` with a not-supported-in-this-version error, so a config written for the full shape fails loudly instead of being dropped by Traefik's decode. `windowcounter` is Redis-only and the only in-memory limiter, `tokenbucket.Memory`, carries the fail-open below. Follow-up: `knowledge/debt/2026-11-20-rate-limit-token-bucket-and-memory-store.md`.
  By: propose
- Q: Can the plugin expose `tokenBucket` at the pinned utilities `v1.0.7`?
  Rank: additive asked — algorithm value of a unit this change creates; requirement Unknowns ("bump … or work around")
  Decision: assumed — no. Measured fail-open at maxDelay 0 under flood (rate 1000/s: 3029 admitted vs 1999); fix is upstream PR #54, open and in no tag; no workaround on the published surface. `algorithm` ships with the single accepted value `slidingWindow` (default); `tokenBucket` and a set `burst` fail `ValidateParams` (Traefik drops unknown keys silently, so omitting the fields would turn a token-bucket config into a sliding window without a word).
  By: propose
- Q: Do the open `windowcounter` defects block building on `v1.0.7`?
  Rank: additive asked — vendoring a package at the existing pin; requirement Unknowns (BUGS.md entries at the pinned tag)
  Decision: assumed — no. Five listed defects are fixed at v1.0.7 (repros pass). Still present: stale previous window in buffered mode across replicas (#63) and EXPIRE not retried in exact mode (#60). Keep the asked `rateLimitSyncRate` default 200ms, document the replica bound, bump later: `knowledge/debt/2026-11-20-bump-utilities-windowcounter-fixes.md`.
  By: explore
- Q: Do `windowcounter` (and `tokenbucket`) run under Yaegi?
  Rank: additive asked — vendored package in the Yaegi load path; requirement Unknowns
  Decision: resolved — upstream `TestYaegi_*` pass at v1.0.7 on yaegi v0.16.1 (flush timer is `time.AfterFunc`, not interpreted `select`). Implement still adds a plugin-side `pkg/yaegitest` program over the vendored copy.
  By: explore
- Q: Who owns the client address, host, and path the bucket keys read?
  Rank: additive asked — key sources of a unit this change creates; requirement key sources (`from: ip | host | path …`)
  Decision: resolved — client address: `pkg/ip.GetRemoteIP` output via `clientrequest.Request.IPAddr()` (prefix masking is a new helper on that `net.IP`, never a re-parse of `RemoteAddr` or forwarded headers); host: `httprule` `requestHostname` (`req.Host` minus port); path: `req.URL.Path`. Reuse those owners.
  By: explore
- Q: Do trusted clients and an action-rule `ban` skip the rate limit?
  Rank: additive asked — position of the new step in `ServeHTTP`; requirement semantics 6
  Decision: resolved — yes. `ServeHTTP` returns before any leg for both, and the README documents trusted clients as skipping the whole plugin. Banned requests are not charged.
  By: explore
- Q: Does `bypassLapi` change rate-limit behaviour?
  Rank: additive asked — new token semantics; requirement semantics 5
  Decision: assumed — no. Each skip token names one leg; only `bypassRateLimit` touches this one.
  By: explore
- Q: Where exactly does the rate limit sit, given captcha is served inside the LAPI and AppSec paths?
  Rank: additive asked — one new step in `ServeHTTP`; requirement semantics 6
  Decision: assumed — between `serveLAPI` and `serveAppSec`. A LAPI captcha decision is still answered by `serveLAPI` before the limit (not charged); the captcha action rule and AppSec run after it. That realises "LAPI → rate limit → captcha → AppSec" for every captcha the plugin decides itself.
  By: explore
- Q: How does the verdict header carry the bucket, and does that diverge from `ban:rules`?
  Rank: bounded asked — `formatRemediationHeader` third-field rule changes; 4 callers enumerated in `pkg/bouncer` (none emit reason `ratelimit` today, so their output is unchanged); requirement semantics 7
  Decision: assumed — `ban:ratelimit:<bucket>` (`deviations.md`). Bucket names reject `:` so consumers still split at most three fields. Divergence: `ban:rules` keeps no rule name; aligning it would change a documented header and is not taken here.
  By: explore
- Q: How are rate-limit drops counted when no LAPI client is bound, and with which labels?
  Rank: additive asked — new origin constant; requirement ("bucket name is used in … metrics")
  Decision: assumed — `recordDropped(req, "plugin:ratelimit:<bucket>", "ban")` on `deny`; failure action `ban` / `captcha` counts origin `plugin:ratelimit_failure` (sibling of `plugin:appsec_failure`); nothing when no LAPI client is bound (same as rule bans today); `log` buckets, skips, and `passthrough` are not drops.
  By: propose
- Q: How does `rateLimitStatusCode` relate to `bouncerRemediationStatusCode`, and which headers go out on a deny?
  Rank: additive asked — new setting and headers; requirement `rateLimitStatusCode`, `rateLimitResponseHeaders`
  Decision: assumed — independent; deny uses `handleBanStatusServeHTTP` with `rateLimitStatusCode` (ban template, body only when the status allows one). `rateLimitResponseHeaders: true` sends `Retry-After` (RFC 9110) = seconds to the bucket's next window boundary, at least 1. `RateLimit-*` (IETF draft) deferred: `knowledge/debt/2026-11-20-rate-limit-ratelimit-response-headers.md`.
  By: propose
- Q: What does a Redis outage cost per request?
  Rank: additive incidental — request-path latency bound of a unit this change creates; no criterion names it
  Decision: assumed — bounded at 250ms per request: one `context.WithTimeout(req.Context(), 250ms)` around the whole rate-limit step (all buckets), and the leg's own `simpleredis.Config` (dial 200ms, command 250ms, pool 8, default retries). `simpleredis` binds the earlier deadline over dial, send, and retries, so the step cannot exceed the budget; a refused port returns sooner; buffered mode touches Redis once per new key per window. No public knob. A backoff gate that skips Redis after repeated failures is not in this slice: `knowledge/debt/2026-11-20-rate-limit-redis-backoff-gate.md`.
  By: propose
- Q: How are several matching buckets evaluated?
  Rank: additive asked — evaluation order of a unit this change creates; requirement semantics 3–4
  Decision: assumed — list order; every matching bucket with a key value is charged until the first `deny` bucket over its limit, which answers and stops (later buckets not charged); `log` buckets never stop; `final: true` stops after that bucket; a missing key value skips the bucket (and its `final`); the first counter error stops the walk and applies the failure action. Denied hits still count (windowcounter increments before comparing), so a flooding client stays limited.
  By: propose
- Q: Do Traefik providers carry the bucket list (list of objects with a nested `key` list) in plugin config?
  Rank: additive asked — config shape of new keys; requirement Unknowns
  Decision: resolved — file provider: yes. Measured by `tests/e2e/real/rate_limit.Tests.ps1` on Traefik v3.7.19 with `config/dynamic/rate-limit.yml` (flat predicates, nested `key` list, string `window`, quoted `requests: "3"` through `WeaklyTypedInput`): 7/7 passed. No Go decode test: `mapstructure` is not a module dependency and `go.mod` stays unchanged (design 15). Docker labels and the Kubernetes CRD stay unmeasured; README shows YAML only and says so.
  By: implement
- Q: Does a `path` predicate on a bucket inherit the ambiguous-path evasion already recorded for ban/captcha rules?
  Rank: additive incidental — predicate reuse; no criterion names it
  Decision: assumed — yes, same `httprule` matching; an alternate encoding can miss a `path`-matched bucket. Existing debt: `knowledge/debt/2026-11-15-ban-captcha-path-rules-ambiguous-path-evasion.md`. A catch-all bucket without `path` is not affected.
  By: explore
- Q: Extract a common leg abstraction before adding this leg?
  Rank: additive incidental — the leg adds one Open call and no alias/Watch copies; the requirement lists the extraction under Out of scope
  Decision: assumed — suggested, not taken: `knowledge/debt/2026-11-20-extract-common-leg-abstraction.md`.
  By: explore
