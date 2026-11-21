# Explore

Two rounds on one bus. Round 2 (2026-11-21: bucket actions, decisions 1–5; addendum B, shared rate-limit leg, decisions B-1..B-4) is on top of each section. Round 1 (2026-11-20) is kept below it as history; where they disagree, round 2 wins (`requirement.md` header).

## Concepts

### Round 2 (worktree @ `d16a2203`, dest `master`)

Units this round touches:

- `plugin.go` — `New`, `openOwned` / `openOwnedLeg`, `claimOwned` / `claimOwnedLeg` / `clearClaimedPublishers`, `openRateLimit`: four published legs wired by hand (a `switch group` arm per leg in three functions, a hand-written rollback list per claim, one `reclaim.Watch` per leg); the rate-limit leg is Open-only beside them (no alias, no Watch, no ClearPublisher). This is where the leg descriptor table goes (B-4).
- `pkg/bouncer/bouncer.go` — `Bouncer` (per leg: `<leg>Bound atomic.Value`, `subscribe<Leg>`, `<leg>Received`, `<leg>ReceiveSeen`, `<leg>InstanceName`; rate limit: plain `rateLimitCounter` set by `AttachRateLimit`, `rateLimitBuckets` compiled per router), `New(next, name, config, subscribeLAPI, subscribeAppSec, subscribeCaptcha, subscribeModsec, log)`.
- `pkg/bouncer/bouncer_leg_{lapi,appsec,captcha,modsec}.go` — the `loaded<Leg>` / `Receive<Leg>` / `receive<Leg>` trio, identical except the client type (diffed: comments and one temp variable differ) and LAPI's stream-scope warning. `bouncer_leg_utils.go` — `storeBinding`, `traceBouncerBinding`.
- `pkg/ratelimit/client.go` — `Client` (limiter + Redis + incarnation string; no `Incarnation()` method), `OwnershipKey(middlewareName, RedisSettings)`, `Open(ctx, middlewareName, RedisSettings, log)` — signature differs from the other four legs' `Open(ctx, cfg, log, name, pluginVersion)` / `OwnershipKey(cfg, name)`.
- `pkg/ratelimit/charge.go` — `Charge(ctx, counter, middlewareName, req, ip)`: list-order walk, count-then-compare, first `deny` stops, `log` collected, `final` stops, first error stops. `bucket_rule.go` / `bucket_set.go` — `ActionDeny` (default) / `ActionLog`; `captcha` rejected at compile.
- `pkg/bouncer/bouncer_serve_ratelimit.go` — `serveRateLimit`, `denyRateLimit`, `applyRateLimitFailureAction`, `captchaRateLimitFailure`.
- `pkg/bouncer/bouncer_serve_captcha.go` — `usableCaptcha`, `handleCaptchaKindServeHTTP` (unsubscribed → per-request WARN + 403 `ban:captcha-downgrade`; unpublished / `!Valid` → same ban, no log; widget asset → continue; valid gate → continue or solved redirect; else challenge page + `recordDropped(origin, "captcha")`), `bypassesCaptcha`.
- `pkg/configuration/configuration.go` — `validateRateLimit` (runs only when `rateLimitEnabled`; checks captcha readiness of `rateLimitFailureAction` on the same router), `validateOpenVsSubscribe` (LAPI, AppSec, Captcha, ModSec only), `captchaInstanceNameReadyAfterOwnerFill`.
- `pkg/logger/debounce.go` — `logger.Debounced` (used at ERROR by ModSec `MsgUnavailable`, 5s).
- `pkg/yaegitest/interpreter.go` + `Makefile` `yaegi_test` (`yaegi test -v .`, root package, CI pins yaegi `v0.16.1`, `.github/workflows/main.yml`).

How they connect after round 2 (proposed shape, not code):

```
owner middleware (rateLimitEnabled, rateLimit* policy, rateLimitInstanceName)
  plugin.New ── descriptor table [lapi, appsec, captcha, modsec, ratelimit]
     ├─ prepare: omitted instance name → Traefik name (owned legs only)
     ├─ open:    reclaim.OpenWithHooks(ownershipKey(cfg, name))   ── ratelimit.Client{limiter, redis,
     │                                                                BucketSet, failureAction, status, headers}
     └─ claim:   SetAlias("alias:ratelimit:<instance>")  ── failure clears every earlier enabled leg
subscriber middleware (bouncerEnabled + rateLimitInstanceName [+ captchaInstanceName])
  plugin.New ── reclaim.Watch(alias, (*ratelimit.Client)(nil), route.ReceiveRateLimit)
  ServeHTTP
    ├─ trusted / rule ban / serveLAPI (unchanged)
    ├─ serveRateLimit
    │    client := loadedRateLimit()        nil → pass through (owner unpublished)
    │    captcha page traffic? (usable captcha: widget asset | challenge marker) → skip every bucket
    │    gateCleared := usableCaptcha().Check(req)   only when the policy has a captcha bucket
    │    client.Buckets().Charge(ctx, client, b.name, req, ip, gateCleared)
    │       key rl:<subscriber name>:<bucket>:<hash>      (B-3, unchanged key shape)
    │    verdict: ratelimit > captcha > log
    │       ratelimit → 429 + Retry-After, ban:ratelimit:<bucket>
    │       captcha   → bypassCaptcha | no usable captcha → answered as ratelimit
    │                   else challenge page, captcha:ratelimit:<bucket>
    ├─ serveAppSec / serveModSec (unchanged)
    └─ next
```

Call sites that matter (roots searched: `plugin.go`, `pkg/`, root `zzz_*_test.go`; `vendor/` and `.pin_diff/` excluded):

- `bouncer.New` with the four `subscribe*` booleans: 15 call sites (plugin.go + tests).
- `Receive<Leg>`: 4 `reclaim.Watch` calls in `plugin.go`; no other production caller.
- `<leg>Bound` / `<leg>Received` / `<leg>ReceiveSeen` read outside the leg files: `pkg/bouncer/bouncer.go` and 6 test files (`zzz_bind_test.go`, `zzz_bypass_captcha_test.go`, `zzz_bypass_rules_test.go`, `zzz_debug_attrs_test.go`, `zzz_forced_decision_test.go`, `zzz_store_binding_test.go`).
- `AttachRateLimit`: 4 references (`bouncer.go`, `plugin.go`, `pkg/bouncer/zzz_rate_limit_test.go`).
- `openRateLimit` / `ratelimit.Open(`: 5 references.
- Generics outside `vendor/`: 0. In `vendor/`: 1 (`reclaim/opentyped.go`, `OpenTyped[T any]`, unused by the plugin).
- Lifecycle lines `crowdsec bouncer bound|unbound` / `crowdsec instance name taken`: asserted only by `tests/e2e/real/instance_severance.Tests.ps1` (T2, F1, F2) and the live spec `core_plugin_middleware_instance-slots` ("Lifecycle logs match e2e grep contract"); no Go unit test asserts them.

Reproduce:

- Round 2 asks for new behaviour (bucket actions, shared leg); nothing fails today: `not reproduced` (no failure claimed).
- Baselines measured on this head: `go test ./...` → all packages `ok`. Root `yaegi test` (yaegi v0.16.1, GOPATH layout via a junction, `GO111MODULE=off`) → `PASS`, exit 0. Note: `yaegi test .` from the module checkout fails with `unable to find source` — the root Yaegi test needs the GOPATH layout CI uses.
- Yaegi v0.16.1 probes (throwaway, scratchpad, not committed), each also run under `go run` where it passed:
  - Generic `Binding[T]` declared and instantiated in one package (struct fields `Binding[*clients.ClientA]` with type args from another package): passes.
  - Generic `leg.Binding[*ClientA]` used as a struct field in another package: Yaegi panics (nil dereference in `interp.nodeType2` / `genType`). Matches the warning in vendored `reclaim/opentyped.go`.
  - Non-generic binding whose `received` field is an interface (`interface{ Incarnation() string }`): Yaegi fails on the third receive (`reflect: call of reflect.Value.Interface on zero Value`); with `received any`: `interface conversion: nil is not …`. `go run` passes both.
  - Non-generic binding that stores the traced incarnation as a `string`, plus a descriptor table of plain structs with func fields (`empty any`, `receive func(*Bouncer) func(any)`): passes under Yaegi and Go with the expected bind / unbind trace sequence.

Outside facts used:

- In-tree: vendored `reclaim/opentyped.go` (Yaegi generic limits), `.github/workflows/main.yml` (yaegi pin), `Makefile` (`yaegi_test`), `README.md` § Middleware Architecture (owner / subscriber split), `openspec/specs/core_plugin_middleware_instance-slots/spec.md`, `openspec/specs/core_plugin_ratelimit_client/spec.md`, `knowledge/devdocs/core_plugin_ratelimit.md`, `knowledge/devdocs/core_plugin_middleware_config-validation.md`, `knowledge/debt/2026-11-20-extract-common-leg-abstraction.md`.
- No new third-party research this round (no new external system).

### Round 1 (history, worktree @ `53950dcb`)

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

### Round 2

Chosen (each is an `assumed` row below unless the human decided it):

- Order of work (B-4): commit 1 = behaviour-preserving extraction of the four published legs onto one descriptor table + one non-generic binding type; commit 2+ = rate-limit leg as the fifth descriptor; then bucket actions.
- Descriptor: a plain struct per leg in `plugin.go` with func fields (group, enabled, instance name, prepare, open, ownership key, Watch empty value, receive hook); iterated by `openOwned`, `claimOwned` (rollback = every earlier enabled entry, which reproduces today's lists), and the Watch loop in `New`. No generics (Yaegi probes).
- Binding: one non-generic `legBinding` type on `Bouncer` (boxed client, subscribe flag, leg, instance name, last traced incarnation as a string, seen flag); per-leg `loaded<Leg>` stays a one-line typed unbox; LAPI keeps its stream-scope warning and `LapiClient` / `SameLapiClient`.
- Published value: `*ratelimit.Client` carries the compiled `BucketSet` and the policy (`rateLimitFailureAction`, `rateLimitStatusCode`, `rateLimitResponseHeaders`); the ownership key covers owner name, Redis settings, sync rate, and that policy. Subscriber carries only `bouncerEnabled` + `rateLimitInstanceName`.
- Counter key unchanged in shape: `rl:<b.name>:<bucket>:<hash>`, `b.name` = the subscribing middleware.
- Unpublished / severed owner: the subscriber passes through.
- Captcha readiness is decided on the subscriber at bind time (ERROR on that transition) and per request (downgrade), not by `ValidateParams`.
- Bucket actions: `ratelimit` (rename of `deny`, default) | `captcha` | `log`; verdict precedence ratelimit > captcha > log; captcha buckets not charged while the gate is valid; captcha page traffic skips every bucket.

Rejected:

- Generic `legBinding[T]` / descriptor — Yaegi v0.16.1 panics when a generic instantiation is named through a package qualifier; works only inside one package, which a `plugin.go` descriptor cannot honour.
- Interface-typed or `any`-typed `received` field — fails under Yaegi v0.16.1 (measured), though correct Go.
- Publishing the Redis Client only and compiling buckets on each subscriber — contradicts B-2 (policy centralized).
- Republishing a changed policy on the same Client — reclaim hands back the existing Client for the same key; mutating it under live requests has no precedent in the four legs.
- Counters keyed by the instance (`rl:<instance>:…`) — B-3 rejects it.
- A startup check on the owner for captcha in the policy — the owner is not the router that serves the captcha.
- `handleBanServeHTTP` (403, no Retry-After, `ban:captcha-downgrade`) as the answer of a downgraded captcha bucket — tells a rate-limited client it is banned.

Live contract: `core_plugin_middleware_instance-slots` (new group `ratelimit`, rollback order, lifecycle logs), `core_plugin_ratelimit_client` (L8/L10 "SHALL NOT be published" reverses), `core_plugin_ratelimit_buckets` (actions), `core_plugin_middleware_bouncer` (verdict header values, pipeline), `core_plugin_middleware_config-validation` (rate-limit keys owner-read, captcha check moves), `core_plugin_lapi_usage-metrics` (captcha bucket drops), `build_e2e_pester_crowdsec-stack` (shared-leg and captcha-bucket cases).

### Round 1 (history)

Superseded by round 2: "Open-only leg" (B-1), the `deny` action name (rename to `ratelimit`), bucket `captcha` deferred (decisions 1–5), "Publishing the limiter as an instance" and "Extracting the leg abstraction now" in Rejected (B-1, B-4).

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

- Q: What does the rate-limit owner publish, and what is its ownership key?
  Rank: additive asked — reshapes `ratelimit.Client` / `OwnershipKey` / `Open`, which round 1 of this same unmerged PR created; B-1 ("published under an instance name") and B-2 ("bucket list and the rest of the rate-limit policy live on the owner")
  Decision: resolved — the human accepted this recommendation (chat 2026-11-21, verbatim: "OK CON TUS PROPUESTAS, IMPLEMENTA"). Options: (a) publish `*ratelimit.Client` that also carries the compiled `BucketSet` and the policy (`rateLimitFailureAction`, `rateLimitStatusCode`, `rateLimitResponseHeaders`), with that policy in the ownership key; (b) publish only the Redis counter and let each subscriber compile its own buckets; (c) keep the key on Redis settings and republish a changed policy on the same Client. Recommend (a). Why: B-2 needs the policy to travel with the published value, and (a) is the captcha precedent (`pkg/captcha/session.go` `ownershipFrom` keys every owner knob, so an owner edit opens a new Client and `SetAlias` repoints subscribers); (b) contradicts B-2; (c) mutates a Client that reclaim hands back for the same key while requests read it. Consequences: key = owner middleware name + Redis host/password/database + sync rate + bucket rows (JSON of `[]BucketRule`) + the three policy settings; a policy edit starts a new incarnation but does not reset counters (Redis keys are `rl:<subscriber>:<bucket>:<hash>` + window start, `pkg/ratelimit/key.go`, independent of the Client); renaming a bucket starts its counters at zero.
  By: propose
- Q: How is the shared leg extracted (B-4): descriptor shape, binding type, and are Go generics usable under Yaegi?
  Rank: bounded asked — changes `bouncer.New` (15 call sites with four `subscribe*` booleans), the per-leg binding fields (read in `bouncer.go` and 6 test files), and the 4 `reclaim.Watch` calls; roots `plugin.go`, `pkg/`, root `zzz_*_test.go`; B-4 ("first a behaviour-preserving commit that moves the four published legs … onto one leg descriptor")
  Decision: resolved — the human accepted this recommendation (chat 2026-11-21, verbatim: "OK CON TUS PROPUESTAS, IMPLEMENTA"). Options: (a) generic `legBinding[T]` + generic descriptor; (b) non-generic binding with an interface-typed `received`; (c) non-generic binding that records the traced incarnation as a string, plus a `plugin.go` table of plain descriptor structs with func fields. Recommend (c). Why (measured on yaegi v0.16.1, the CI pin): (a) works only when the generic type is declared and instantiated in one package and panics (`interp.nodeType2`) when named through a package qualifier, the limit vendored `reclaim/opentyped.go` already documents; (b) fails at runtime under Yaegi (`reflect.Value.Interface on zero Value`) though Go passes; (c) passes under Yaegi and Go with the expected trace sequence. Descriptor fields: group, enabled(cfg), instanceName(cfg), prepare, open, ownershipKey (AppSec's `appsec.Key` assigned there, no rename), Watch empty value, receive hook. Per-leg extras stay as hooks: LAPI's stream-scope warning, `LapiClient` / `SameLapiClient`. Rollback: a claim failure clears every earlier enabled entry in table order — identical to today's hand lists (AppSec→LAPI; captcha→LAPI, AppSec; ModSec→LAPI, AppSec, captcha); the spec line "Captcha-claim failure SHALL also ClearPublisher ModSec" stays vacuously true (ModSec claims after captcha). Rate limit is appended last, so it gains `ClearPublisher` when its flag drops (round 1 lacked it). Risk of (c): the trace no longer holds the previous Client pointer, so a reused address could skip one TRACE line; the bound value itself is unaffected. Implement adds a `pkg/yaegitest` program over the real binding + descriptor before the refactor commit lands. Propose (change `share-rate-limit-leg-and-bucket-actions`, design decisions 1–3): `bouncer.New` takes one `bouncer.Subscriptions` value (one bool per leg) instead of the four `subscribe*` booleans, so the rate-limit leg adds a field and no call-site churn.
  By: propose
- Q: What proves that the extraction commit preserves behaviour for LAPI, AppSec, captcha, and ModSec?
  Rank: additive asked — tests only; B-4 ("existing tests green")
  Decision: resolved — the human accepted this recommendation (chat 2026-11-21, verbatim: "OK CON TUS PROPUESTAS, IMPLEMENTA"). On the extraction commit alone, before any rate-limit change: (1) `go test ./...` (baseline all `ok`, measured); (2) root `yaegi test` in the GOPATH layout CI uses (baseline `PASS`, measured; `yaegi test .` from the module checkout does not find sources); (3) a new unit test that pins, per leg, the `crowdsec bouncer bound|unbound` trace attrs (`traefikName`, `leg`, `instanceName`, `incarnation`) and the claim-rollback order — no Go test pins either today, only e2e greps; (4) local Pester `instance_severance`, `captcha`, `bypass_captcha`, `modsec`, `appsec`, `waf_dual`, `failure_action` (port remap per the repo's local-e2e note). Existing tests are edited only where they read the removed per-leg fields or call `bouncer.New` with four booleans, and each edit is mechanical.
  By: propose
- Q: What does a subscriber do with its own `rateLimit*` settings?
  Rank: additive asked — validation of keys this PR created; B-2 ("the bucket list and the rest of the rate-limit policy live on the owner"); Out of scope "Per-subscriber overrides … not asked"
  Decision: resolved — the human accepted this recommendation (chat 2026-11-21, verbatim: "OK CON TUS PROPUESTAS, IMPLEMENTA"). Options: (a) ignore them as owner-read leftovers; (b) fail startup when a non-owner sets any; (c) allow overrides. Recommend (a). Why: same rule the plugin already applies to `captcha*` and owner-read `modsec*` leftovers on subscribers (`validateOpenVsSubscribe` comments), `validateRateLimit` already runs only when `rateLimitEnabled`, and the owner prefers resilience over startup failures; (c) is out of scope. Add the symmetric E2 row: a leftover `rateLimitInstanceName` with neither `bouncerEnabled` nor `rateLimitEnabled` fails `New`, as for the other four legs. README states that `rateLimit*` is read on the owner only, the one leg whose request-time answers live on the owner.
  By: propose
- Q: What does `rateLimitEnabled` mean after B-1, and what fills an omitted `rateLimitInstanceName`?
  Rank: additive asked — meaning of a key this PR created (unreleased); B-1 ("an owner middleware Opens it and publishes it … routers subscribe with `bouncerEnabled` + the instance name")
  Decision: resolved — the human accepted this recommendation (chat 2026-11-21, verbatim: "OK CON TUS PROPUESTAS, IMPLEMENTA"). Own only (Open + `SetAlias` on group `ratelimit`), like `captchaEnabled`; charging needs `bouncerEnabled` + `rateLimitInstanceName`. A new `ratelimit.Prepare` fills an omitted name with the Traefik name when owned, so the round-1 single-middleware config (`rateLimitEnabled` + `bouncerEnabled`, no name) subscribes to its own alias and keeps charging under its own name with the same Redis keys. Propose: the fill lives in `plugin.go` (the rate-limit descriptor's prepare), not in `pkg/ratelimit`, because `pkg/configuration` imports `pkg/ratelimit` (`Config.RateLimitBuckets`), so a `ratelimit.Prepare(*configuration.Config, …)` would be an import cycle (design decision 4).
  By: propose
- Q: What does a subscriber do while its owner is unpublished, or after it went away?
  Rank: additive asked — request path of the leg this PR creates; B-1 (shared leg with Watch / Receive)
  Decision: resolved — the human accepted this recommendation (chat 2026-11-21, verbatim: "OK CON TUS PROPUESTAS, IMPLEMENTA"). Options: (a) pass through (charge nothing); (b) apply a failure action — the subscriber has none of its own after B-2, so this needs a new router key such as `bouncerRateLimitFailureAction`; (c) ban. Recommend (a). Why: until the owner publishes, the subscriber has no bucket to charge and no policy to read; (a) equals the leg's default failure action (`passthrough`) and today's nil-counter skip; the owner prefers resilience. It differs on purpose from AppSec / LAPI / ModSec, whose unpublished answer is a router setting (`bouncer*FailureAction`). Bind / unbind is traced at TRACE (`crowdsec bouncer bound|unbound`, `leg: ratelimit`), never per request. (b) is a new key nobody asked for; record it as a follow-up if the human wants a fail-closed subscriber.
  By: propose
- Q: Where is captcha readiness of the rate-limit policy checked, now that the policy is on the owner and the captcha subscription on the subscriber?
  Rank: additive incidental — moves validation of `rateLimitFailureAction: captcha`, a contract this unmerged PR created; round-2 Out of scope lists "Changing `rateLimitFailureAction: captcha`" as not asked, so no criterion names the move
  Decision: resolved — the human accepted this recommendation (chat 2026-11-21, verbatim: "OK CON TUS PROPUESTAS, IMPLEMENTA"). Options: (a) keep `captchaInstanceNameReadyAfterOwnerFill` on the owner; (b) check on the subscriber at startup; (c) no startup check: when the rate-limit Client binds on a subscriber whose policy needs a captcha (a `captcha` bucket or failure action `captcha`) and the router has no captcha subscription, log ERROR once on that bind; at request time the captcha answer downgrades (row below). Recommend (c). Why: (a) checks the router that does not serve the captcha (an owner with `bouncerEnabled: false` needs no captcha); (b) is impossible — the subscriber learns the owner's policy only at publish; (c) is decision 3's resilience rule applied to both captcha uses of the leg, which also removes the tension "two behaviours for captcha on a router without a captcha". Propose records this as a deviation (Out-of-scope row reversed by B-2). Propose: recorded in `deviations.md` (row "no startup check for captcha in the rate-limit policy").
  By: propose
- Q: "Counters per subscribing router" (B-3): per subscriber middleware or per Traefik router?
  Rank: additive asked — counter key of a unit this PR created; B-3 (`rl:<subscribing router middleware name>:<bucket>:<hash>`)
  Decision: resolved — the human accepted this recommendation (chat 2026-11-21, verbatim: "OK CON TUS PROPUESTAS, IMPLEMENTA"). Per subscribing middleware: `Charge` keeps `b.name`, the name Traefik passes to `New`. Traefik routers that reference the same subscriber middleware share one budget (live spec "Two routers that use the same middleware SHALL share one counter"). Per Traefik router is not available: `New` receives the middleware name, not the router.
  By: propose
- Q: Does the rate-limit Client gain `Incarnation()`?
  Rank: additive asked — method on a type this PR created; B-1 (shared leg, bind / unbind traces)
  Decision: resolved — the human accepted this recommendation (chat 2026-11-21, verbatim: "OK CON TUS PROPUESTAS, IMPLEMENTA"). Yes: a nil-safe getter returning the existing incarnation string, as the other four Clients have (`pkg/{lapi,appsec,captcha,modsecurity}`). Its lifecycle lines (`crowdsec ratelimit instance started|sleeping|waking|closed`) gain `instanceName`, the attr the instance-slots lifecycle contract lists.
  By: propose
- Q: What does a `captcha` bucket answer on a router without a usable captcha (downgrade), and with a `bypassCaptcha` rule?
  Rank: additive asked — new action value of a unit this PR created; decisions 2 and 3
  Decision: resolved — the human accepted this recommendation (chat 2026-11-21, verbatim: "OK CON TUS PROPUESTAS, IMPLEMENTA"). Options: (a) the existing downgrade (`handleBanServeHTTP`: `bouncerRemediationStatusCode` 403, no `Retry-After`, `ban:captcha-downgrade`); (b) answer as `ratelimit`: `rateLimitStatusCode` (429) + `Retry-After` + `ban:ratelimit:<bucket>`, drop `ban` under `plugin:ratelimit:<bucket>`. Recommend (b), the same answer decision 2 gives `bypassCaptcha`. Why: the client is rate limited, not banned; (b) keeps the bucket in the header and the retry hint; the requirement itself calls 429 + `Retry-After` "the natural reading".
  By: propose
- Q: How often is the downgrade ERROR logged (decision 3)?
  Rank: additive asked — logging of a path this PR creates; decision 3 sub-point
  Decision: resolved — the human accepted this recommendation (chat 2026-11-21, verbatim: "OK CON TUS PROPUESTAS, IMPLEMENTA"). ERROR once on the bind transition when the policy needs a captcha and the router has no captcha subscription (static misconfiguration, row above); `logger.Debounced` ERROR every 5s (the ModSec `MsgUnavailable` precedent) when the router subscribes but the captcha client is unpublished or `!Valid` (transient); DEBUG per request. The bucket path checks `usableCaptcha` itself, so the existing per-request WARN `crowdsec bouncer captcha unsubscribed` does not fire from it; that WARN on the other paths is not changed (Bound the ask). Propose: the rate-limit failure action `captcha` is the leg's second captcha use, so it follows the same logging (bind ERROR, debounced ERROR, DEBUG per request) and skips that WARN too; its answer stays the existing `ban:captcha-downgrade`. Without this, a subscriber with no captcha whose owner sets failure action `captcha` would WARN on every request of a Redis outage, which `core_plugin_ratelimit_client` forbids (design decision 9).
  By: propose
- Q: When a `captcha` bucket is over its limit for an unsolved client, does the walk stop?
  Rank: additive asked — evaluation order of a unit this PR created; addendum "Hard ceiling = stacking"
  Decision: resolved — the human accepted this recommendation (chat 2026-11-21, verbatim: "OK CON TUS PROPUESTAS, IMPLEMENTA"). Options: (a) stop like `ratelimit`; (b) record the first captcha bucket and keep walking; a later `ratelimit` bucket over its limit wins. Recommend (b): precedence ratelimit > captcha > log, `final` still stops, a counter error still stops and applies the failure action. Why: the stacked hard ceiling then holds in any list order and also for a client that never solves; Redis cost equals a normal walk.
  By: propose
- Q: How does decision 4 (no counting by captcha buckets while the gate is valid) fit `Charge`?
  Rank: additive asked — signature of a function this PR created; decision 4
  Decision: resolved — the human accepted this recommendation (chat 2026-11-21, verbatim: "OK CON TUS PROPUESTAS, IMPLEMENTA"). `serveRateLimit` computes `gateCleared` once per request with `usableCaptcha().Check(req)` only when the policy has a captcha bucket, and passes it to `Charge`, which skips (does not `Take`) captcha buckets when set. Cost: one HMAC check of the gate cookie per request, only on such routers. No usable captcha → nothing is exempt.
  By: propose
- Q: How is the captcha page's own traffic (decision 5) recognised, and where?
  Rank: additive asked — new skip in a step this PR created; decision 5
  Decision: resolved — the human accepted this recommendation (chat 2026-11-21, verbatim: "OK CON TUS PROPUESTAS, IMPLEMENTA"). Before `Charge`, when the router has a usable captcha: `IsCustomResourceRequest` (widget assets; exists only for the `custom` provider, the others load widgets from the provider's host) or `HasChallengeMarker` (verification POST, also the second-tab submit) skips every bucket. Without a usable captcha there is no captcha page, so no exemption. A custom template without the marker is counted (documented). The post-solve 302 → GET is an ordinary request and is counted. Tension kept: a client that always posts the marker is never limited and each POST costs a provider siteverify call; propose writes a debt note for it (decision 5 is the human's). Propose: `knowledge/debt/2026-11-21-rate-limit-captcha-marker-flood.md` and its `issues.md` row.
  By: propose
- Q: Which drop metrics do captcha buckets record?
  Rank: additive asked — new origin use; requirement Unknowns (metrics)
  Decision: resolved — the human accepted this recommendation (chat 2026-11-21, verbatim: "OK CON TUS PROPUESTAS, IMPLEMENTA"). challenge page: `captcha` under `plugin:ratelimit:<bucket>` (via `handleCaptchaKindServeHTTP`); downgrade and `bypassCaptcha` → 429: `ban` under the same origin; a cleared-gate pass is not a drop.
  By: propose
- Q: How does a captcha bucket interact with a captcha action rule, a LAPI captcha decision, and a Redis error mid-walk?
  Rank: additive asked — pipeline of a step this PR created; requirement Unknowns
  Decision: resolved — the human accepted this recommendation (chat 2026-11-21, verbatim: "OK CON TUS PROPUESTAS, IMPLEMENTA"). LAPI captcha decisions are answered in `serveLAPI` before the rate limit and charge nothing (unchanged); a captcha bucket verdict on a request that also matched a captcha action rule serves the bucket's challenge (`captcha:ratelimit:<bucket>`), and a `ratelimit` verdict still warns `warnCaptchaSuperseded` (unchanged); a counter error stops the walk and the failure action wins over any captcha verdict collected so far (round-1 rule).
  By: propose
- Q: Does round 2 change the per-request INFO of `log` buckets?
  Rank: additive incidental — logging of a path this PR created; not raised by the human
  Decision: resolved — the human accepted this recommendation (chat 2026-11-21, verbatim: "OK CON TUS PROPUESTAS, IMPLEMENTA"). No. A `log` bucket is a dry run whose lines exist to be read; "log on transitions" is the owner's rule for gates. Not touched (Bound the ask).
  By: propose
- Q: How are the leg-abstraction debt note ("three legs") and its `issues.md` row corrected?
  Rank: additive asked — run bus and a debt file this run wrote; B-4 (takes the debt note)
  Decision: resolved — the human accepted this recommendation (chat 2026-11-21, verbatim: "OK CON TUS PROPUESTAS, IMPLEMENTA"). Implement marks the row `[x]` with a `Taken:` line naming the four published legs plus the rate-limit leg, and deletes `knowledge/debt/2026-11-20-extract-common-leg-abstraction.md`; same for the `rate-limit-captcha-action` row and file (round-2 Housekeeping). The card reads `issues.md`, so nothing else needs the four-leg correction.
  By: propose
- Q: What is the e2e shape for the shared leg?
  Rank: additive asked — new Pester cases; B-2, B-3, decision 5 ("needs a real-stack e2e test")
  Decision: resolved — the human accepted this recommendation (chat 2026-11-21, verbatim: "OK CON TUS PROPUESTAS, IMPLEMENTA"). A new dynamic file on the Dragonfly stack: owner `rl-owner` (`rateLimitEnabled`, `rateLimitSyncRate: "0"`, buckets, `rateLimitInstanceName: rl-shared`, `bouncerEnabled: false`) and two subscribers `rl-sub-a` / `rl-sub-b` (`bouncerEnabled` + `rateLimitInstanceName: rl-shared`, no `rateLimit*` keys) on separate routers. Cases: both subscribers answer 429 `ban:ratelimit:<bucket>` at N+1 (one policy); exhausting A leaves B's full budget for the same client address (B-3); severance with the `instance_severance` harness (`Write-SevYaml`): remove the owner → after `reclaimGraceSeconds` subscribers pass through and logs show `crowdsec bouncer unbound` with `"leg":"ratelimit"`, re-add → bound and limited again; an owner bucket edit → new incarnation, subscribers rebound, counters not reset. Captcha-bucket cases (decisions 1–5) on a subscriber that also subscribes to the stack's `custom` dummy captcha. One client address per case via `X-Forwarded-For` (round-1 rule).
  By: propose
- Q: Does the existing `bypass` action also skip the rate limit?
  Rank: additive asked — new `bypassRateLimit` token and `SkipRateLimit` field in `pkg/httprule/action.go`; requirement semantics 5 and open decision 1
  Decision: assumed — no. Only `bypassRateLimit` skips the rate limit; `bypass` keeps meaning "skip LAPI and AppSec". The `Fold` skip guard change has 1 caller (`pkg/bouncer/bouncer.go:196`).
  By: explore
- Q: Should buckets support `action: captcha` in this PR?
  Rank: additive asked — new action value on a unit this change creates; requirement open decision 2
  Decision: resolved — yes, by the human in round 2 (decisions 1–5, chat 2026-11-21): actions `ratelimit` (rename of `deny`, default, no alias) | `captcha` | `log`; session = `captchaGracePeriodSeconds`; `bypassCaptcha` → 429; no usable captcha → runtime downgrade + ERROR; captcha buckets do not count while the gate is valid; captcha page traffic never counted. Round 1 had assumed no (debt `knowledge/debt/2026-11-20-rate-limit-captcha-action.md`, taken this round). Open sub-points are the round-2 rows above.
  By: explore
- Q: What does the leg do when Redis is unreachable?
  Rank: additive asked — new per-router setting; requirement open decision 3
  Decision: assumed — `rateLimitFailureAction` default `passthrough` (fail open), also accepting `ban` and `captcha` via the existing validator (`deviations.md`). Applied whenever `Take` returns an error, including buffered mode's retained flush error; the first error stops the bucket walk and the local verdict that came with it is ignored. A failure-action captcha honours `bypassCaptcha`, as the LAPI and AppSec failure captchas do (design decision 11). Round 2: the setting is read from the owner's published policy (row "What does the rate-limit owner publish"); `captcha` is no longer checked at startup: ERROR once when the Client binds on a router without a captcha subscription, then the existing `ban:captcha-downgrade` at request time with the leg's own logging (rows "Where is captcha readiness … checked" and "How often is the downgrade ERROR logged").
  By: propose
- Q: Do empty `rateLimitRedis*` settings default to `lapiRedis*`?
  Rank: additive asked — new config keys; requirement open decision 4
  Decision: assumed — no. Separate, explicit settings mirroring `lapiRedisHost/Password/PasswordFile/Database` (no read hosts: windowcounter writes on every path).
  By: explore
- Q: How are key values stored in Redis?
  Rank: additive asked — key format of a unit this change creates; requirement open decision 5
  Decision: assumed — hashed: `<prefix>:<middleware name>:<bucket>:<sha256 hex prefix of the joined key parts>`, windowcounter appends `:<window start>`. The middleware name keeps two middlewares with the same bucket name apart while replicas of one middleware still share. Round 2: the middleware name is the subscribing middleware's (B-3).
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
  Decision: assumed — `ban:ratelimit:<bucket>` (`deviations.md`). Bucket names reject `:` so consumers still split at most three fields. Divergence: `ban:rules` keeps no rule name; aligning it would change a documented header and is not taken here. Round 2 adds `captcha:ratelimit:<bucket>` for a captcha bucket's challenge, through the same formatter.
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
  Decision: assumed — list order; every matching bucket with a key value is charged until the first `deny` bucket over its limit, which answers and stops (later buckets not charged); `log` buckets never stop; `final: true` stops after that bucket; a missing key value skips the bucket (and its `final`); the first counter error stops the walk and applies the failure action. Denied hits still count (windowcounter increments before comparing), so a flooding client stays limited. Round 2: `deny` is renamed `ratelimit`; captcha buckets follow the row "When a `captcha` bucket is over its limit …".
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
  Decision: resolved — yes, by the human in round 2 addendum B (B-4, chat 2026-11-21): extract it in this PR as a behaviour-preserving first commit over the four published legs, then add the rate-limit leg as one more descriptor. Takes `knowledge/debt/2026-11-20-extract-common-leg-abstraction.md`. Shape: row "How is the shared leg extracted (B-4) …".
  By: explore
- Q: Who validates the challenge-form POST of a captcha bucket on a router that does not subscribe to AppSec?
  Rank: additive asked — request path of a step this PR created (`serveRateLimit`, design 6(b)); decision 5 assumed the marker POST is validated ("each POST costs a provider siteverify call", "the post-solve 302 → GET is counted"), but on a router without AppSec nothing after `serveRateLimit` validates it.
  Decision: blocked — measured on real Traefik v3.7.19 (implement group 4, `tests/e2e/real/rate_limit_captcha.Tests.ps1`, router `/rl-captcha/` with its own custom-provider captcha and no AppSec): after `captcha:ratelimit:per-ip-soft`, the stack's challenge form (`crowdsec_captcha_challenge=v1&dummy-captcha-response=ok`, the marker every stock and e2e template posts) gets 200 from the whoami origin, which echoes the form body; no `crowdsec_captcha_gate`, no `captcha:solved`. The same POST without the marker is charged, reaches `answerCaptchaBucket`, and gets 302 `captcha:solved` with the cookie. So a browser can never solve a captcha bucket on such a router, and the form body reaches the application. Only routers that subscribe to AppSec validate it (`answerAppSec` → `isCaptchaFormAnswer`). Options: (a) `serveRateLimit` hands a marker POST with a usable captcha to the captcha gate (`handleCaptchaKindServeHTTP`) instead of continuing, as `answerAppSec` does — needs a header and drop origin for a failed verification, since no bucket answered; (b) one owner for "a marker POST with a usable captcha never reaches origin: the gate validates it" in `ServeHTTP` after every leg, which also covers a LAPI captcha decision that expired between page and POST. Not decided here: design 6(b) says "continue".
  By: implement
