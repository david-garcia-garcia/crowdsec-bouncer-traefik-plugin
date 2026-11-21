# Requirement
IssueKey: 2026-11-20-add-redis-rate-limit-leg

Two rounds on the same ticket, branch, and PR #228.

- **Round 1** (2026-11-20): the caller spec (`ticket/source.md`), copied in full, then its grounding sections (suffixed `— round 1`). Implemented, reviewed, OpenSpec change `add-redis-rate-limit-leg` archived and synced. Kept as history; its grounding was measured on `origin/master` @ `44e2151b`.
- **Round 2** (2026-11-21): the caller spec addendum (`ticket/source-round2.md`), copied in full, then the live grounding sections `## Current (code)`, `## Out of scope`, `## Unknowns`, `## Tensions`. Where round 2 and round 1 disagree, round 2 wins (it replaces the bucket actions and answers round-1 open decision 2).

---

# Caller spec — 2026-11-20-add-redis-rate-limit-leg

## Human ask (verbatim, chat 2026-11-20)

> i want to add a ratelimit leg to the bouncer, so we have a complete waf. this is the official one
> https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/ratelimit/, but I want
> something MORE efficient, that is distributed (Redis based). I worked on a BASE implementation we could
> reuse in https://github.com/david-garcia-garcia/traefik-middleware-utilities, that was taken from KONG.
>
> Also, for this ratelimiter, I want better bucketing rules than the official plugin, i.e. i want a rule
> of bucket selectors, i.e.
>
> ```
> bucket1:
>   - valueFrom: header
>     key: HOST
>     match: .*
>   - valueFrom: path
>     match: *.css, *.js
> bucket2:
>   -
> ```
>
> before implementing, propose the shape of the config

Then: "USE OPD-workflow to propose a PR" (full run).

## Config shape proposed in chat (the design to implement)

```yaml
rateLimitEnabled: true
rateLimitStore: redis                 # redis | memory
rateLimitRedisHost: redis:6379        # mirrors lapiRedis* fields, separate settings
rateLimitRedisPassword: ""
rateLimitRedisPasswordFile: ""
rateLimitRedisDatabase: ""
rateLimitSyncRate: 200ms              # slidingWindow only. 0 = exact (one Redis call per request)
rateLimitFailureAction: allow         # allow | deny when Redis is unreachable
rateLimitStatusCode: 429
rateLimitResponseHeaders: true        # Retry-After (+ RateLimit-* headers)

rateLimitBuckets:
  - name: login                       # required, unique; used in Redis key, logs, verdict header, metrics
    match:                            # same predicates as bouncerActionRules (httprule.Rule, RE2); omitted = every request
      method: POST
      path: ^/(login|wp-login\.php)$
    key:                              # what the counter is per; parts are joined
      - from: ip
        ipv6Prefix: 64
    algorithm: slidingWindow          # slidingWindow (Kong, windowcounter) | tokenBucket (Traefik, tokenbucket)
    requests: 5
    window: 1m
    action: deny                      # deny (429) | captcha | log (dry run)
  - name: static-assets
    match:
      path: \.(css|js|png|svg|woff2?)$
    key:
      - from: ip
      - from: host
    requests: 600
    window: 1m
    final: true                       # matched → stop evaluating later buckets
  - name: api-per-token
    match:
      host: ^api\.example\.com$
      headers:
        Authorization: ""             # present
    key:
      - from: header
        name: Authorization
    algorithm: tokenBucket
    requests: 50
    window: 1s
    burst: 100
  - name: tenant
    key:
      - from: path
        pattern: ^/t/([^/]+)/         # capture group 1 is the key; no match = bucket skipped
    requests: 1000
    window: 1m
  - name: per-ip-default
    key:
      - from: ip
    requests: 300
    window: 1m
```

Key sources (`from`): `ip` (with `ipv4Prefix` / `ipv6Prefix`), `header`, `cookie`, `query`, `host`, `path`,
`method`; each takes an optional `pattern` with a capture group. Empty `key` list = one global counter for the bucket.

Semantics proposed:

1. `match` (which requests) and `key` (what the counter is per) are separate. The human's sketch mixed them.
2. `match` reuses `httprule.Rule` → RE2, not globs (`*.css, *.js` → `\.(css|js)$`).
3. All matching buckets count, in list order; the first one over its limit denies; `final: true` stops evaluation.
4. A missing key value (header/cookie/capture absent) skips that bucket.
5. Exemptions via `bouncerActionRules` with a new `bypassRateLimit` token.
6. Pipeline position: action rules → LAPI → **rate limit** → captcha → AppSec.
7. Verdict header: `ratelimit:<bucket>` on 429; `captcha:ratelimit:<bucket>` when action is captcha.

Facts measured in chat about traefik-middleware-utilities (local clone D:\repositories\traefik-middleware-utilities):

- `windowcounter` (Kong sliding window) is Redis-only; with syncRate > 0 it buffers locally and flushes on a ticker
  (GET only on first sight of a key). `Take(ctx, key, limit, window)`; one Limiter can serve every bucket.
- `tokenbucket` (Traefik Lua copy) has `NewMemory` and `NewRedis(rate, burst, maxDelay, ttl)`; one EVAL per request.
- Both packages carry a `BUGS.md` of reproduced bugs (tokenbucket #1 is a high-severity fail-open). Which are fixed in the
  version this repo pins was NOT verified — must be checked before building on them.
- windowcounter rejects/truncates non-whole-second windows (bug #6) → validation must require whole seconds for slidingWindow.
- No in-memory sliding window exists.

## Open decisions — ASSUMED (human did not answer; conductor's recommendation, revisit at review)

1. Does the existing `bypass` action also skip the rate limit? **Assumed: no.** Only the new `bypassRateLimit` token
   skips it, so `bypass` keeps its current meaning for existing users.
2. `action: captcha` exemption after a solved captcha: **Assumed: out of scope for this change.** Ship `deny` and `log`;
   `captcha` only if it falls out cheaply, else record as follow-up.
3. Redis outage: **Assumed: `rateLimitFailureAction: allow` default** (fail open, same stance as the AppSec backoff gate).
4. `rateLimitRedis*` defaulting to `lapiRedis*` when empty: **Assumed: no — separate, explicit settings.**
5. Redis keys hash the key value (`rl:<bucket>:<sha256-prefix>`): **Assumed: yes.**
6. `rateLimitStore: memory` with `slidingWindow`: **Assumed: reject at config validation** (only tokenBucket is in-memory) unless an in-memory sliding window is trivial.

## Repo constraints known from memory

- The owner wants this plugin to be a single edge WAF; the rate limiter belongs here as a leg (not a sibling plugin).
- Before adding another leg, suggest extracting a common leg abstraction (per-leg copy-paste in plugin.go switches and Bouncer fields).
- PRs target `master` (origin/main mirrors upstream). PR and CI go through GitHub MCP tools, not `gh`.

---

## Current (code) — round 1

Measured on `origin/master` @ `44e2151b` in this worktree. One entry path per claim.

- Rate limit leg / `rateLimit*` config keys — `not found` (no `rateLimit` field in `pkg/configuration/configuration.go`; no rate limiter package under `pkg/`).
- Leg wiring: legs are `lapi`, `appsec`, `captcha`, each switched by name in `plugin.go` (`legLAPI`/`legAppSec`/`legCaptcha`, `openOwnedLeg`, `claimOwnedLeg`, one `reclaim.Watch` per leg) and held as per-leg `*Bound` / `*Received` / `*ReceiveSeen` / `subscribe*` fields on `Bouncer` — `pkg/bouncer/bouncer.go`. Common leg abstraction — `not found`.
- Request pipeline: enabled check → client IP → trusted clients skip everything → action-rule ban → `serveLAPI` → `serveAppSec` → next — `pkg/bouncer/bouncer.go` (`ServeHTTP`). Captcha is not its own stage: it is served as a remediation from the LAPI and AppSec paths — `pkg/bouncer/bouncer_serve_remediation.go`, `pkg/bouncer/bouncer_serve_captcha.go`.
- `match` predicates to reuse: `httprule.Rule` {method, path, host, headers, cookies}, RE2, set fields AND, empty header/cookie pattern = present — `pkg/httprule/rule.go`, `pkg/httprule/set.go` (`compileValuePredicates`, `matchValuePredicates`).
- Action tokens: `ban`, `captcha`, `bypass`, `bypassLapi`, `bypassAppsec`, `bypassCaptcha` — `pkg/httprule/action.go`. `bypassRateLimit` — `not found`.
- Redis settings to mirror: `lapiRedisEnabled/Host/Password/PasswordFile/Database/ReadHosts`; the password file is read only when Redis is enabled — `pkg/configuration/configuration.go` (fields ~L136-141, `ValidateParams` ~L389).
- Redis client already in use: vendored `simpleredis` through `decisionstore` — `pkg/decisionstore/redis.go`.
- Failure-action vocabulary today: `passthrough | ban | captcha` (empty = ban) — `pkg/configuration/configuration.go` (`validateFailureAction`, `EffectiveFailureAction`).
- Verdict header: closed `kind:reason[:origin]` tokens; kinds `ban | captcha | error`; origin only for reason `lapi` — `pkg/bouncer/remediation_header.go`.
- Drop metrics: `recordDropped` → LAPI client `IncDropped(origin, ipType, remediation)`, only when a LAPI client is bound; rule origins are `plugin:rules:<name>` — `pkg/bouncer/bouncer_serve_remediation.go`, `pkg/lapi/client_metrics.go`.
- Response status: one `bouncerRemediationStatusCode` for ban responses — `pkg/bouncer/bouncer_serve_remediation.go` (`handleBanStatusServeHTTP`). `Retry-After` / `RateLimit-*` response headers — `not found`.
- IPv4/IPv6 prefix keying helper — `not found` (`pkg/ip/checker.go` has CIDR membership checks only).
- Utilities module pin: `github.com/david-garcia-garcia/traefik-middleware-utilities v1.0.7` — `go.mod`. Vendored packages are `iplookup`, `reclaim`, `simpleredis`, `traefikemulator` only — `vendor/modules.txt`. `windowcounter` and `tokenbucket` exist in the module at tag `v1.0.7` but are not vendored (local clone `D:\repositories\traefik-middleware-utilities`, `git ls-tree v1.0.7`).
- Upstream API at `v1.0.7` (local clone, measured): `windowcounter.New(*simpleredis.SimpleRedis, syncRate)`, `(*Limiter).Take(ctx, key, limit, window) (allowed, estimated, err)`; `tokenbucket.NewMemory(rate, burst, maxDelay, ttl)`, `tokenbucket.NewRedis(redis, rate, burst, maxDelay, ttl)`, `Allow(ctx, key) (bool, time.Duration, error)` — one tokenbucket limiter per rate, so one per bucket.
- Upstream `BUGS.md` for both packages: untracked files in the local clone, in no tag (`v1.0.7`, `v1.0.8`); no commit touches `tokenbucket/` or `windowcounter/` between `v1.0.7` and upstream `master`.
- Existing rate-limit knowledge: CrowdSec AppSec `RateLimit()` helper (CrowdSec v1.8.2, in-memory per engine, 429 relayed through the AppSec leg) — `knowledge/research/ext_crowdsec_appsec_rate-limit/notes.md`, `pkg/bouncer/bouncer_serve_appsec_verdict.go`.
- Leg naming debt already recorded — `knowledge/debt/2026-09-23-leg-instance-backend-vocabulary.md`.

## Out of scope — round 1

Inferred extras, listed and not taken:

- Captcha exemption after a solved captcha for `action: captcha` buckets (spec open decision 2 assumes out of scope; ship `captcha` only if cheap).
- Extracting a common leg abstraction from `plugin.go` / `Bouncer` (spec "Repo constraints" says to *suggest* it before adding a leg; doing it is a separate decision).
- Fixing upstream `windowcounter` / `tokenbucket` bugs inside traefik-middleware-utilities (separate repo).
- In-memory sliding window (spec decision 6: reject at validation unless trivial).
- Defaulting `rateLimitRedis*` to `lapiRedis*` (spec decision 4: no).
- Sending rate-limit hits to CrowdSec as signals, alerts, or LAPI decisions — not asked.
- Publishing the rate limit leg as a shared instance (`*InstanceName` reclaim alias like the other legs) — not asked.

## Unknowns — round 1

Explore owns these.

- Which `BUGS.md` entries are real and unfixed at the pinned tag, and whether the plugin must bump the utilities module (and vendor `windowcounter` / `tokenbucket`) or work around them. Tokenbucket #1 is described as a high-severity fail-open.
- Whether `windowcounter` and `tokenbucket` run under Yaegi (Traefik's plugin interpreter) at `v1.0.7`; upstream carries `*_yaegi_test.go` files, result not measured here.
- Whether trusted clients (`bouncerClientTrustedIPs`) and the action-rule `ban` early return skip the rate limit; the spec places the leg after LAPI but does not say.
- Whether `bypassLapi` changes rate-limit behavior (spec decision 1 covers only `bypass`).
- Redis load per request (buckets × requests), `syncRate` accuracy across replicas, and behavior when a buffered flush fails.
- Rate-limit drop metrics when no LAPI client is bound (current `recordDropped` is LAPI-bound) and the origin label to use (spec says the bucket name is used in metrics).
- How `rateLimitStatusCode` relates to `bouncerRemediationStatusCode` and the ban template (429 body vs ban page).
- Memory growth of `tokenbucket.NewMemory` under high-cardinality keys (header, query, cookie values).
- Whether Traefik's providers (file, labels, CRD) carry a list of objects with nested lists in plugin config as the spec shape needs — not measured.

## Tensions — round 1

- The human sketch mixes match and key selection (`valueFrom: header … match: .*`) and uses globs (`*.css, *.js`); the proposed design splits `match` / `key` and uses RE2 (spec semantics 1–2).
- Failure-action vocabulary: spec `rateLimitFailureAction: allow | deny`; existing legs use `passthrough | ban | captcha` (`pkg/configuration/configuration.go`).
- Verdict header: spec `ratelimit:<bucket>` / `captcha:ratelimit:<bucket>` adds a new kind and puts a free-form name in the reason slot; current header is a closed `kind:reason[:origin]` set with origin only for `lapi` (`pkg/bouncer/remediation_header.go`).
- Pipeline position "LAPI → rate limit → captcha → AppSec": in code captcha is a remediation served inside the LAPI / AppSec paths, not a stage between them (`pkg/bouncer/bouncer.go`).
- The spec's library facts were measured on the local clone; the pinned module has the code but does not vendor it, so using it changes `vendor/` (and maybe the module version).
- The spec's `BUGS.md` facts come from untracked local notes in the utilities clone, not from any released tag.
- The owner asked to *propose the config shape before implementing*; the chat proposal is recorded here as the design with six assumed answers the human did not confirm.

---

# Caller spec addendum — 2026-11-20-add-redis-rate-limit-leg, round 2 (2026-11-21)

Same ticket, same branch, same PR #228. The first round (rate-limit leg, `deny | log`) is implemented, reviewed,
its OpenSpec change `add-redis-rate-limit-leg` archived and synced. This round changes the bucket actions.

## Human ask (verbatim, chat 2026-11-21)

> can we not have an action for each bucket, such as "ratelimit" or "captcha" (ratelimit is the response=

The conductor proposed (chat):

| `action` | Response | Verdict header |
|---|---|---|
| `ratelimit` (default) | `rateLimitStatusCode` (429) + `Retry-After` | `ban:ratelimit:<bucket>` |
| `captcha` | the plugin's captcha page; a client that has solved it gets through | `captcha:ratelimit:<bucket>` |
| `log` | lets the request through, only logs at INFO | — |

- Rename `deny` → `ratelimit`. PR #228 is unmerged, so `deny` has no users: rename, no alias.
- Bucket `captcha` reuses the captcha path the failure action already uses (`captchaRateLimitFailure` in
  `pkg/bouncer/bouncer_serve_ratelimit.go`: gate, widget assets, cleared gate, bypassCaptcha).
- Hard ceiling = stacking: a `captcha` bucket plus a `ratelimit` bucket on the same key
  (e.g. per-ip-soft 300/min captcha, per-ip-hard 1200/min ratelimit). No new fields.

Example the human saw:

```yaml
rateLimitBuckets:
  - name: per-ip-soft
    requests: 300
    window: 1m
    action: captcha
    key:
      - from: ip
  - name: per-ip-hard
    requests: 1200
    window: 1m
    action: ratelimit
    key:
      - from: ip
  - name: per-network
    requests: 5000
    window: 1m
    action: log
    key:
      - from: ip
        ipv6Prefix: 64
```

## Human decisions (verbatim answers, chat 2026-11-21) — these are DECIDED, not assumed

> 1. Correct, it reuses cptchaGracePeriodSeconds
> 2. ok
> 3. I prefer a resiilent plugin, instead of what you proposed, use a downgrade but log an ERROR.
> 4. No counting while exempt
> 5. true
>
> Implement

Meaning of each, against the questions the conductor asked:

1. **Captcha session lifetime:** a solve lasts the existing captcha session, `captchaGracePeriodSeconds`. No new setting.
2. **API routes with `bypassCaptcha`:** a bucket with `action: captcha` acts as `ratelimit` (429 + Retry-After,
   verdict `ban:ratelimit:<bucket>`) on requests that a `bypassCaptcha` rule matches. Differs on purpose from
   `bypassCaptcha` elsewhere ("let it through"): a rate limit must not become unlimited.
3. **`action: captcha` on a router without a captcha:** do NOT fail at startup. Downgrade at request time using
   the existing downgrade path (`ban:captcha-downgrade` style — serve the ban/429 instead), and log at ERROR.
   Resilience over strictness. (Decide in explore/propose: status code of the downgrade — the bucket's
   `rateLimitStatusCode` 429 + Retry-After is the natural reading for a rate-limit bucket; and log rate — an ERROR
   per request may flood; the owner's standing rule for gates is "log on transitions, never per request", so
   consider once-per-bucket/at-startup ERROR plus DEBUG per request, and record the choice.)
4. **Counting while exempt:** a client that has solved the captcha (valid gate within captchaGracePeriodSeconds)
   is NOT counted by `captcha` buckets. It is still counted by `ratelimit` and `log` buckets.
5. **Captcha traffic:** the captcha page's own requests (widget assets, verification POST) must never be counted
   or blocked by any bucket. Needs a real-stack e2e test.

Also in scope (conductor proposal, accepted with "Implement"): real-stack e2e covering captcha → solve → hard 429
on stacked buckets, using the stack's existing captcha test provider setup (see #223/#226 e2e for how captcha is
solved in Pester).

## Housekeeping

- The debt note `knowledge/debt/2026-11-20-rate-limit-captcha-action.md` and its issues.md row are taken by this
  round: close the row and delete the debt file when this lands (per opd-workflow § Issues).
- README "Limits of this version" currently says `action: captcha` fails at startup — must change.
- The open-question row "captcha action out of scope" (explore) is now decided by the human.

---

## Current (code)

Round 2. Measured on the PR #228 head (`88f8efbd`, round 1 merged into the branch; `origin/master` @ `82498271` is its ancestor and has no rate-limit code: `git grep rateLimitBuckets origin/master` finds nothing, and no tag contains the branch head, so `deny` is unreleased). One entry path per claim.

Decisions 1–5 above are the human's (chat 2026-11-21), **decided**, not assumptions. The two sub-points decision 3 hands to explore/propose (downgrade status code, log rate) are listed under `## Unknowns`.

Bucket actions (`deny` → `ratelimit`, add `captcha`):

- `deny` / `log` constants — `pkg/ratelimit/bucket_rule.go` (`ActionDeny = "deny"` is the default, `ActionLog`). `ratelimit` action token — `not found`. `captcha` action constant — `not found`.
- Validation — `pkg/ratelimit/bucket_set.go` (`compileBucketAction`: empty → `deny`; `deny` and `log` pass; `captcha` fails with `action: captcha is not supported in this version`; anything else fails `action: must be one of "deny" or "log"`).
- Charging — `pkg/ratelimit/charge.go` (`Charge`): walks matching buckets in list order; a bucket whose key has no value is skipped; `counter.Take` counts **before** the compare ("a denied hit still counts"); the first `deny` over its limit sets `Verdict.DenyBucket` + `RetryAfter` and stops the walk; a `log` over its limit is appended to `Verdict.Exceeded` and the walk goes on; `final` stops the walk; the first counter error stops the walk (`Verdict.Err`). `Verdict` has no field for a captcha bucket — `not found`.
- Serving a deny — `pkg/bouncer/bouncer_serve_ratelimit.go` (`serveRateLimit` → `denyRateLimit`): `Retry-After` when `rateLimitResponseHeaders`, then `handleBanStatusServeHTTP` with `rateLimitStatusCode`, header reason `ratelimit` (`ban:ratelimit:<bucket>`), origin `lapi.OriginPluginRateLimit(bucket)` (`plugin:ratelimit:<bucket>`); `warnCaptchaSuperseded` when a `captcha` action rule also matched.
- Log bucket — `pkg/bouncer/bouncer_serve_ratelimit.go` (`msgRateLimitExceeded`, INFO `crowdsec bouncer rate limit exceeded` per exceeded bucket per request).
- `deny` in docs — `README.md` (L697 verdict table `action: deny`; L908 "Order" paragraph; L918 "Limits of this version": "`action: captcha` on a bucket fail[s] at startup"; L1297 `RateLimitBuckets` reference "`action` (`deny` by default, or `log`)"; L446 and L1315/L1318 say "rate-limit deny" in prose).
- `deny` in live specs — `openspec/specs/core_plugin_ratelimit_buckets/spec.md` (L60, L65 default, L111 "`action` SHALL accept only `deny` and `log`", L118 scenario `action: captcha` fails); `openspec/specs/core_plugin_middleware_bouncer/spec.md` (L257, L348, L700, L710); `openspec/specs/core_plugin_middleware_config-validation/spec.md` (L477); `openspec/specs/core_plugin_lapi_usage-metrics/spec.md` (L209); `openspec/specs/build_e2e_pester_crowdsec-stack/spec.md` (L269, L272).
- `deny` in devdocs — `knowledge/devdocs/core_plugin_ratelimit.md` (L10 "`action` (`deny` | `log`)"; L11 `_Avoid_: … per-bucket captcha`; L32 the serve path).
- `deny` in tests — `pkg/ratelimit/zzz_bucket_set_test.go` (L90 default), `tests/e2e/real/rate_limit.Tests.ps1` (Context "deny bucket"), `tests/e2e/real/config/dynamic/rate-limit.yml` (bucket `login` relies on the default; no explicit `action: deny`).

Captcha path the bucket `captcha` would reuse:

- `captchaRateLimitFailure` — `pkg/bouncer/bouncer_serve_ratelimit.go`: `bypassesCaptcha` → returns false (request continues); else `handleCaptchaKindServeHTTP(ReasonRateLimit, headerReasonRateLimitFailure, OriginPluginRateLimitFailure)`. Reached only from `applyRateLimitFailureAction` (counter error), not from an over-limit bucket.
- Gate / downgrade — `pkg/bouncer/bouncer_serve_captcha.go` (`handleCaptchaKindServeHTTP`): router not subscribed to a captcha → WARN `crowdsec bouncer captcha unsubscribed` on **every** such request, then `handleBanServeHTTP` (status `bouncerRemediationStatusCode`, header `ban:captcha-downgrade`); subscribed but no published / `!Valid` client → same ban, no log; same-origin widget asset → false (continue); valid gate + challenge marker → `WriteSolvedRedirect` (302, `captcha:solved`); valid gate → false (continue); otherwise `recordDropped(origin, "captcha")` and the challenge page (HTTP 200) with header `captcha:<reason>[:<third>]`.
- Downgrade header — `pkg/bouncer/remediation_header.go` (`headerReasonCaptchaDowngrade = "captcha-downgrade"`; `headerThirdField` gives a third field only to reasons `lapi` and `ratelimit`, so `ban:captcha-downgrade` carries no bucket name). `captcha:ratelimit:<bucket>` already formats through `formatRemediationHeader` with kind `captcha` + reason `ratelimit`; no caller passes that pair today.
- Downgrade status and `Retry-After` — `pkg/bouncer/bouncer_serve_remediation.go` (`handleBanServeHTTP` uses `bouncerRemediationStatusCode`; only `handleBanStatusServeHTTP` takes another code). A downgrade path that answers 429 + `Retry-After` — `not found`.
- Whether a router "has a captcha" — `plugin.go` L124 (`subscribeCaptcha := config.BouncerEnabled && config.CaptchaInstanceName != ""`), known at `New`; whether the client is usable — `pkg/bouncer/bouncer_serve_captcha.go` (`usableCaptcha`: subscribed, published, `Valid`), known only per request.
- Startup check for captcha on the failure action — `pkg/configuration/configuration.go` (`validateFailureAction` + `captchaInstanceNameReadyAfterOwnerFill`: `rateLimitFailureAction: captcha` without a captcha instance name **fails `ValidateParams`**).
- Cleared gate — `pkg/captcha/captcha.go` (`Client.Check`) → `pkg/captcha/gate.go` (`validateGateValue`: HMAC of the `crowdsec_captcha_gate` cookie, issued time + `gracePeriodSeconds`, optional IP binding). Only callable on a usable client.
- `captchaGracePeriodSeconds` — `pkg/configuration/configuration.go` (L125 field, L289 default `86400`); carried into the client by `pkg/captcha/session.go` (L61, L159); also the gate cookie `maxAge` set on a pass in `pkg/captcha/captcha.go` (`ServeHTTP`).
- `bypassCaptcha` — token in `pkg/httprule/action.go`; folded into `ActionMatch.BypassCaptchaName`; consumed by `pkg/bouncer/bouncer_serve_captcha.go` (`bypassesCaptcha`, TRACE, the caller writes nothing and continues). Every current consumer lets the request through (`remediateUnderActionRules`, `serveAppsecCaptchaGate`, `captchaRateLimitFailure`). A consumer that turns `bypassCaptcha` into a ban/429 — `not found`.
- Captcha page's own requests — widget assets: `pkg/captcha/captcha.go` (`IsCustomResourceRequest`, exact paths stored by `storeCustomResourcePaths` for the `custom` provider only); verification POST: `pkg/captcha/captcha.go` (`HasChallengeMarker`, `crowdsec_captcha_challenge=v1`, posted to the same URL the challenge was served on; `Validate` reads the provider token field). Router-level helper — `pkg/bouncer/bouncer_serve_captcha.go` (`isCaptchaFormAnswer`). A rate-limit exemption for either — `not found`: `serveRateLimit` charges every matching bucket before any captcha check.
- Pipeline — `pkg/bouncer/bouncer.go` (`ServeHTTP`): trusted clients → action-rule ban → `serveLAPI` (a LAPI captcha decision is answered here, before the rate limit) → `serveRateLimit` → `serveAppSec` → `serveModSec` → next.
- Drop metrics — `pkg/bouncer/bouncer_serve_remediation.go` (`handleBanStatusServeHTTP` → `recordDropped(origin, "ban")`), `pkg/bouncer/bouncer_serve_captcha.go` (`recordDropped(origin, "captcha")` on the challenge page); spec `openspec/specs/core_plugin_lapi_usage-metrics/spec.md` L209 (rate-limit deny = `ban` under `plugin:ratelimit:<bucket>`; captcha bucket — `not found`).
- Debounced logging helper — `pkg/logger/debounce.go` (`logger.Debounced`). A once-per-bucket or at-startup ERROR for an unusable captcha — `not found`.

Tests and housekeeping:

- Captcha solve in Pester — `tests/e2e/real/captcha.Tests.ps1` (POST `dummy-captcha-response=ok`, with or without `crowdsec_captcha_challenge=v1`; asserts `Set-Cookie: crowdsec_captcha_gate=`); custom provider routes — `tests/e2e/real/config/dynamic/bypass-captcha.yml` (`captchaProvider: custom`, `captchaCustomValidateUrl: http://dummy-captcha/siteverify`); verifier — `tests/e2e/real/config/dummy-captcha.py`.
- Rate-limit e2e — `tests/e2e/real/rate_limit.Tests.ps1`, `tests/e2e/real/config/dynamic/rate-limit.yml` (Dragonfly, `rateLimitSyncRate: "0"`, four routers, none with a captcha). A rate-limit router with a captcha — `not found`.
- Debt note taken by this round — `knowledge/debt/2026-11-20-rate-limit-captcha-action.md`; its row — run `issues.md` (`note large … rate-limit-captcha-action.md`); the round-1 open question — run `explore.md` (L106–108, "Should buckets support `action: captcha` in this PR?", assumed no).

## Out of scope

Round 2, inferred extras, listed and not taken:

- An alias or deprecation path for `deny` (addendum: rename, no alias).
- New fields for a hard ceiling (addendum: stacking only, "No new fields").
- A new captcha session setting (decision 1: reuse `captchaGracePeriodSeconds`).
- Changing `bypassCaptcha` anywhere outside a `captcha` bucket (decision 2 scopes the different meaning to buckets).
- Changing `rateLimitFailureAction: captcha`, which still fails at startup without a captcha instance name (see `## Tensions`); not asked.
- Exempting CrowdSec AppSec's own challenge traffic (`/crowdsec-internal/challenge/`) from buckets: decision 5 names the captcha page's requests (widget assets, verification POST), not AppSec's challenge.
- The other round-1 debt notes (`tokenBucket` / memory store, `RateLimit-*` headers, Redis backoff gate, windowcounter bump, common leg abstraction, single-reading-path spec): not reopened.

## Unknowns

Explore owns these.

- Downgrade status code (decision 3 sub-point, left to explore/propose): the bucket's `rateLimitStatusCode` + `Retry-After` vs the existing downgrade's `bouncerRemediationStatusCode`; and the header: `ban:captcha-downgrade` (no bucket) vs `ban:ratelimit:<bucket>`.
- Log rate of the ERROR (decision 3 sub-point): once per bucket at startup (only `subscribeCaptcha` is known then), once per transition, `logger.Debounced`, plus DEBUG per request; and whether the existing per-request WARN `crowdsec bouncer captcha unsubscribed` also fires.
- Walk semantics for a `captcha` bucket over its limit on an unsolved client: stop the walk like `ratelimit` (later stacked buckets not counted while the client sees challenge pages) or keep counting so the hard bucket still fills. The stacking example only works as described if the soft bucket comes first.
- How decision 4 fits `Charge`: today `Take` runs before the compare, so "not counted while exempt" needs the gate check before charging `captcha` buckets (a cleared-gate input to `Charge`, or a per-bucket skip). Cost of `Check` (HMAC) per request.
- How decision 5 is detected on every bucket: widget assets are known only for the `custom` provider; a verification POST is recognised by the challenge marker, which custom templates may lack (`warnIfChallengeMarkerMissing` only warns); a solve POST without the marker looks like origin traffic. Also whether the exemption applies when the router has no usable captcha.
- Whether the post-solve 302 → GET (and a second-tab submit) are "captcha traffic" or ordinary requests.
- Drop metrics for a `captcha` bucket (origin `plugin:ratelimit:<bucket>`, remediation `captcha`?) and for its downgrade and its `bypassCaptcha` → ratelimit answer.
- Interaction with a `captcha` action rule matching the same request (today `warnCaptchaSuperseded` on a deny), with a LAPI captcha decision (answered before the rate limit), and with `rateLimitFailureAction` when Redis errors mid-walk.
- `log` bucket INFO per request vs the "never per request" rule — not raised by the human; whether round 2 touches it.
- E2E shape: how the stack's dummy captcha and Dragonfly combine on one router; client-address isolation per case (round-1 rule) with a gate cookie possibly bound to IP.

## Tensions

- Decision 5 ("never counted or blocked by any bucket") vs decision 2's rationale ("a rate limit must not become unlimited"): a client that always sends the challenge marker, or only fetches widget assets, is never limited by any bucket, and each verification POST costs a call to the captcha provider.
- Decision 3 (runtime downgrade + ERROR, no startup failure) vs `rateLimitFailureAction: captcha`, which fails `ValidateParams` without a captcha instance name (`pkg/configuration/configuration.go`): two behaviours for "captcha on a router without a captcha" in the same leg.
- Decision 3 "log an ERROR" vs the owner's rule for gates "log on transitions, never per request" (cited in the addendum) and the existing per-request WARN on an unsubscribed downgrade (`pkg/bouncer/bouncer_serve_captcha.go`).
- Decision 3 "use the existing downgrade path" vs that path's answer: `bouncerRemediationStatusCode` (403 by default), no `Retry-After`, header `ban:captcha-downgrade` without the bucket, while a rate-limit bucket answers `rateLimitStatusCode` (429) + `Retry-After` + `ban:ratelimit:<bucket>`.
- Decision 2 (`bypassCaptcha` on a `captcha` bucket → 429) vs every current `bypassCaptcha` consumer, including the leg's own `captchaRateLimitFailure`, which lets the request through (`pkg/bouncer/bouncer_serve_ratelimit.go`). The human chose the difference on purpose; the failure-action path keeps the old meaning.
- Decision 4 accepts what the round-1 debt note warned about (`knowledge/debt/2026-11-20-rate-limit-captcha-action.md`): a bot that solved one captcha is exempt from `captcha` buckets for `captchaGracePeriodSeconds` (default 86400s). The addendum's answer is stacking a `ratelimit` bucket; nothing enforces that a `captcha` bucket has one.
- Rename vs synced specs: round 1's archived and synced specs, README, devdocs, and e2e all say `deny` (see `## Current (code)`); the rename touches live `openspec/specs/*` that round 1 just wrote, plus the devdocs `_Avoid_` term "per-bucket captcha".
- Header vocabulary: the round-1 caller spec (semantics 7) and the addendum table name `captcha:ratelimit:<bucket>`, but no README, live spec, or devdoc lists it (`grep` finds none); it is a new value in the closed table of `openspec/specs/core_plugin_middleware_bouncer/spec.md` and `README.md` (L697 area).
