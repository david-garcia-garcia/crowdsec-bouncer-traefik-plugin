# Requirement
IssueKey: 2026-11-20-add-redis-rate-limit-leg

The caller spec below is a complete product design and is copied in full (`ticket/source.md`). Sections after it are grounding by prepare.

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

## Current (code)

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

## Out of scope

Inferred extras, listed and not taken:

- Captcha exemption after a solved captcha for `action: captcha` buckets (spec open decision 2 assumes out of scope; ship `captcha` only if cheap).
- Extracting a common leg abstraction from `plugin.go` / `Bouncer` (spec "Repo constraints" says to *suggest* it before adding a leg; doing it is a separate decision).
- Fixing upstream `windowcounter` / `tokenbucket` bugs inside traefik-middleware-utilities (separate repo).
- In-memory sliding window (spec decision 6: reject at validation unless trivial).
- Defaulting `rateLimitRedis*` to `lapiRedis*` (spec decision 4: no).
- Sending rate-limit hits to CrowdSec as signals, alerts, or LAPI decisions — not asked.
- Publishing the rate limit leg as a shared instance (`*InstanceName` reclaim alias like the other legs) — not asked.

## Unknowns

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

## Tensions

- The human sketch mixes match and key selection (`valueFrom: header … match: .*`) and uses globs (`*.css, *.js`); the proposed design splits `match` / `key` and uses RE2 (spec semantics 1–2).
- Failure-action vocabulary: spec `rateLimitFailureAction: allow | deny`; existing legs use `passthrough | ban | captcha` (`pkg/configuration/configuration.go`).
- Verdict header: spec `ratelimit:<bucket>` / `captcha:ratelimit:<bucket>` adds a new kind and puts a free-form name in the reason slot; current header is a closed `kind:reason[:origin]` set with origin only for `lapi` (`pkg/bouncer/remediation_header.go`).
- Pipeline position "LAPI → rate limit → captcha → AppSec": in code captcha is a remediation served inside the LAPI / AppSec paths, not a stage between them (`pkg/bouncer/bouncer.go`).
- The spec's library facts were measured on the local clone; the pinned module has the code but does not vendor it, so using it changes `vendor/` (and maybe the module version).
- The spec's `BUGS.md` facts come from untracked local notes in the utilities clone, not from any released tag.
- The owner asked to *propose the config shape before implementing*; the chat proposal is recorded here as the design with six assumed answers the human did not confirm.
