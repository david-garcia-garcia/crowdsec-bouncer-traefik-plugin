# Requirement
IssueKey: 2026-11-20-add-redis-rate-limit-leg

Two rounds on the same ticket, branch, and PR #228.

- **Round 1** (2026-11-20): the caller spec (`ticket/source.md`), copied in full, then its grounding sections (suffixed `— round 1`). Implemented, reviewed, OpenSpec change `add-redis-rate-limit-leg` archived and synced. Kept as history; its grounding was measured on `origin/master` @ `44e2151b`.
- **Round 2** (2026-11-21): the caller spec addendum (`ticket/source-round2.md`), copied in full, then the live grounding sections `## Current (code)`, `## Out of scope`, `## Unknowns`, `## Tensions`. Where round 2 and round 1 disagree, round 2 wins (it replaces the bucket actions and answers round-1 open decision 2).
  - **Addendum B** (2026-11-21, added after round-2 prepare, before explore; appended to `ticket/source-round2.md`): the rate-limit leg becomes a shared leg published under an instance name like LAPI, AppSec, captcha and ModSec, with the policy centralized on the owner, counters keyed per subscribing router, and the common leg abstraction extracted first in this PR. Copied in full after the round-2 addendum's `## Housekeeping`; grounded in the same live sections (rows marked "addendum B"). It reverses round 1's "Open-only" rate-limit leg and its out-of-scope row.
  - **Addendum C** (2026-11-22, added after round-2 code review and its two human-decided fixes; appended to `ticket/source-round2.md`): the operator chooses the counting algorithm for the whole limiter, `tokenBucket` or the sliding window, on the owner. Copied in full after addendum B's conductor assumptions; grounded in the same live sections (rows marked "addendum C"). It takes the `tokenBucket` half of the round-1 debt note `knowledge/debt/2026-11-20-rate-limit-token-bucket-and-memory-store.md`; the memory store stays out of scope.

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

# Round 2 addendum B — the rate-limit leg is a shared leg (2026-11-21)

Same round, same branch, same PR #228. Added after round-2 prepare, before explore. Round 2 now carries both the
bucket actions above and this addendum.

## Human ask (verbatim, chat 2026-11-21)

The conductor quoted the round-1 debt note `knowledge/debt/2026-11-20-extract-common-leg-abstraction.md`
("The rate-limit leg … is Open-only: it is not published under an instance name (requirement Out of scope) …").
The human answered:

> el ratelimiter SÍ que necesita ser shared, como el resto de legs

Asked what the owner shares with subscribed routers, the human answered (verbatim):

> lo que pasa es que tengo varias topologías de aplicación, todas con la misma configuración de buckets, etc. y me
> gustaría que eso estuviera centralizdo

## Human decisions (chat 2026-11-21) — DECIDED, not assumed

1. **Shared leg.** The rate-limit leg is published under an instance name like LAPI, AppSec, captcha and ModSec:
   an owner middleware Opens it and publishes it (`SetAlias`); routers subscribe (`Watch` / `Receive`) with
   `bouncerEnabled` + the instance name. Round 1's "Open-only" shape and its out-of-scope row
   ("Publishing the rate limit leg as a shared instance … not asked") are reversed.
2. **Centralized policy.** The bucket list and the rest of the rate-limit policy live on the owner, so several
   application topologies share one configuration. (Conductor reading, to confirm in explore: the owner carries the
   Redis connection, `rateLimitSyncRate`, `rateLimitBuckets`, `rateLimitFailureAction`, `rateLimitStatusCode`,
   `rateLimitResponseHeaders`; a subscriber carries only the instance name.)
3. **Counters per subscribing router** (option chosen: "Por router (Recomendado)"). Same policy, each application
   keeps its own budget: the counter key stays `rl:<subscribing router middleware name>:<bucket>:<hash>`, so a
   client that exhausts a limit on app A still has its full budget on app B. Not `rl:<instance>:…`.
4. **Extract the common leg abstraction in this PR** (option chosen: "Extraer en este PR (Recomendado)"):
   first a behaviour-preserving commit that moves the four published legs (LAPI, AppSec, captcha, ModSec) onto one
   leg descriptor (existing tests green), then the rate-limit leg enters as one more descriptor. No fifth hand copy.
   This takes the debt note `knowledge/debt/2026-11-20-extract-common-leg-abstraction.md` (close its `issues.md`
   row, delete the file). Note: that debt note says "three existing legs"; the code has four (ModSec included).

## Conductor assumptions for this round (human did not answer; revisit at review)

- The instance-name setting follows the other legs' naming (`rateLimitInstanceName`), and the own / bounce axes
  follow `plugin.go`'s existing rules (`rateLimitEnabled` = own, `bouncerEnabled` + instance name = bounce).
- The captcha-bucket behaviour of this round (downgrade, `bypassCaptcha`, gate check) is decided per request on the
  **subscribing** router (its captcha subscription), not on the owner.
- Not in this round: the single-EVAL + local over-limit-cache load design, Redis TLS / ACL user settings
  (simpleredis v1.0.9 supports them), and `RateLimit-*` headers. Each stays a follow-up.

---

# Round 2 addendum C — limiter-level algorithm: tokenBucket or slidingWindow (2026-11-22)

Same round, same branch, same PR #228. Added after round-2 codereview and its two human-decided fixes.

## Human ask (verbatim, chat 2026-11-22)

> Una cosa no me queda clara de la implementacion, donde elige el usuario si el ratelimiter es tockenbut o windowcounter¿?

The conductor answered that only the sliding window exists (per-bucket `algorithm` only rejects `tokenBucket`), and
recommended a separate PR. The human answered:

> lo quiero en este PR porque esto es clave, el cuando el usuario configura el ratelimit debe poder configurarlo (no a
> nivel de bucket sino de todo el limiter) si quiere usar tokenbucket o windowcounter

## Conductor correction recorded

The conductor first said the utilities library has no Redis token bucket. That was wrong: utilities `v1.0.10` (already
pinned) has `tokenbucket.Redis` (Traefik's Lua token bucket via `simpleredis` EVAL, `NewRedis(redis, rate, burst,
maxDelay, ttl)`, `Allow(ctx, key) (Status, error)`) and `tokenbucket.Memory`; `tokenbucket.Status` carries Allowed, Limit
(= burst), Remaining, Period, Reset, RetryAfter, Delay. The over-admit defect of the round-1 debt note
(`knowledge/debt/2026-11-20-rate-limit-token-bucket-and-memory-store.md`) is fixed by utilities PR #54, tagged in v1.0.9.
`tokenbucket` is not vendored yet (not imported).

## Human decision — DECIDED

- The algorithm is chosen for the whole limiter, not per bucket: `tokenBucket` or the sliding window (`windowcounter`).

## Conductor design proposal (sent to the human, who did not object; treat as assumed, revisit at review)

- New owner setting `rateLimitAlgorithm: slidingWindow | tokenBucket`, default `slidingWindow`. It is part of the
  centralized policy published by the owner (and of the ownership key); subscribers use the owner's algorithm.
- Buckets keep `requests` per `window` for both algorithms; with `tokenBucket` it means a refill rate of
  `requests / window` per second.
- Optional per-bucket `burst`, valid only with `tokenBucket`, default = `requests`. One `tokenbucket.Redis` per bucket
  (rate and burst are fixed at `NewRedis`), `maxDelay` 0 (no queuing, deny instead), a TTL that covers a full refill.
- The per-bucket `algorithm` key goes away; setting it fails startup with a message pointing at `rateLimitAlgorithm`.
- `rateLimitSyncRate` applies only to `slidingWindow` (the token bucket is one Redis EVAL per counted bucket);
  documented, not rejected (its default is `200ms`).
- Unchanged: actions `ratelimit | captcha | log`, precedence, `Retry-After` (from the token bucket's `RetryAfter`,
  rounded up, at least 1s), failure action, counters per subscribing router, key prefix `rl:<router>:<bucket>:<hash>`
  (the token bucket's Redis hash key must not collide with sliding-window keys of the same bucket after an algorithm
  switch — decide a distinguishing suffix).
- Out of scope: `rateLimitStore: memory` (not asked; per-replica; `tokenbucket.Memory` makes it a small follow-up).

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

Shared rate-limit leg (addendum B). Measured on the branch head `417f2785` (round 2 so far: utilities bumped to v1.0.10, Retry-After from the counter; no bucket-action or shared-leg code yet; `origin/master` still `82498271`). One entry path per claim.

How the four published legs are wired today:

- Leg group names — `plugin.go` (`legLAPI = "lapi"`, `legAppSec = "appsec"`, `legCaptcha = "captcha"`, `legModsec = "modsec"`); alias string `alias:<leg>:<instanceName>` — `plugin.go` (`instanceAlias`). A rate-limit leg constant or alias group — `not found`.
- Instance-name owner fill — `pkg/captcha/session.go` (`Prepare`: `captchaEnabled` and an empty `captchaInstanceName` → the Traefik name); the other three legs' `Prepare` do the same fill, and `plugin.go` `New` calls all four by hand before `openOwned`. A rate-limit `Prepare` — `not found`.
- Own axis — `plugin.go` (`openOwned` → `openOwnedLeg`): fixed order LAPI, AppSec, captcha, ModSec; a leg whose `*Enabled` is false gets `reclaim.ClearPublisher(name, group)`; an enabled leg hits a `switch group` arm calling `lapi.Open` / `appsec.Open` / `captcha.Open` / `modsecurity.Open` with `(bindCtx, config, log, name, pluginVersion)`.
- Publish and rollback — `plugin.go` (`claimOwned` → `claimOwnedLeg` → `claimAlias` → `reclaim.SetAlias(key, instanceAlias(group, instanceName), publisher, group)`; a taken name logs ERROR `crowdsec instance name taken` and fails `New`). Rollback is written by hand: each later claim failure calls `clearClaimedPublishers` with the earlier legs (LAPI; LAPI + AppSec; LAPI + AppSec + captcha), which re-reads each leg's `*Enabled` in its own `switch`.
- Ownership keys per leg — `plugin.go` (`claimOwnedLeg`: `lapi.OwnershipKey(config, name)`, `appsec.Key(config, name)` (AppSec has no `OwnershipKey` name), `captcha.OwnershipKey(config, name)`, `modsecurity.OwnershipKey(config, name)`). Each hashes the owner's middleware name plus owner knobs, e.g. `pkg/captcha/session.go` (`ownershipFrom`: `MiddlewareName`, provider, keys, `GracePeriodSeconds`, …).
- Bounce axis — `plugin.go` (`New`: `subscribe<Leg> := config.BouncerEnabled && config.<Leg>InstanceName != ""` four times, passed to `bouncer.New`, then one `reclaim.Watch(ctx, instanceAlias(leg, name), (*<pkg>.Client)(nil), route.Receive<Leg>)` per subscribed leg). An owner with `bouncerEnabled` subscribes to its own alias because `Prepare` filled the name.
- `bouncer.New` signature — `pkg/bouncer/bouncer.go` (`New(next, name, config, subscribeLAPI, subscribeAppSec, subscribeCaptcha, subscribeModsec bool, log)`).
- Per-leg router state — `pkg/bouncer/bouncer.go` (`Bouncer`: `<leg>Bound atomic.Value`, `subscribe<Leg> bool`, `<leg>Received *<pkg>.Client`, `<leg>ReceiveSeen bool`, `<leg>InstanceName string` for each of the four; one `bindingMu` for all).
- Per-leg receive trio — `pkg/bouncer/bouncer_leg_captcha.go` (`loadedCaptcha` = `reclaim.Unbox(&b.captchaBound)`; `ReceiveCaptcha(published any)` = guard on `subscribeCaptcha`, `storeBinding`, `receiveCaptcha`; `receiveCaptcha` traces bind / unbind under `bindingMu` with the Client's `Incarnation()`). The same trio is copied in `bouncer_leg_lapi.go` (plus a header-scope warning in `receiveLAPI`, and `LapiClient` / `SameLapiClient`), `bouncer_leg_appsec.go`, `bouncer_leg_modsec.go`; shared helpers in `pkg/bouncer/bouncer_leg_utils.go` (`storeBinding`, `traceBouncerBinding`).
- Common leg abstraction (one descriptor iterated by `openOwned` / `claimOwned` / `New`, one binding type on `Bouncer`) — `not found`. Go generics in `plugin.go` or `pkg/` — `not found` (`grep '\[T '`); whether Yaegi runs a generic binding type — not measured.
- Published-leg contract — `openspec/specs/core_plugin_middleware_instance-slots/spec.md` (L83 "Captcha publishes on reclaim group captcha", L119 "ModSec publishes on reclaim group modsec": exclusive publish, generation-aware Clear, multi-leg rollback, and "Captcha-claim failure SHALL also `ClearPublisher` ModSec"). A rate-limit group — `not found`.
- Owner / subscriber split in user docs — `README.md` (L464–476: connection table with four rows LAPI, AppSec, captcha, ModSec; "A middleware that only protects … keeps its own request settings (status code, captcha, trusted IPs, behavior when CrowdSec or a WAF is down, response headers)"; "all four can be called `shared`"). A rate-limit row — `not found`.
- Leftover-setting checks — `pkg/configuration/configuration.go` (`validateOpenVsSubscribe` → `validateLegOpenVsSubscribe` for LAPI, AppSec, Captcha, ModSec only: a leftover instance name or secret fails only when neither `bouncerEnabled` nor the leg's `*Enabled` is set; owner-read settings on a subscriber are not checked, "leftover captcha* is not a secret", "leftover owner-read modsec* is not a secret"). A rate-limit entry — `not found`.
- Captcha readiness on a router — `pkg/configuration/configuration.go` (`captchaInstanceNameReadyAfterOwnerFill`: true when `captchaInstanceName` is set or `captchaEnabled` will fill it; evaluated on the router whose config is being validated).

How the rate-limit leg is wired today:

- Open — `plugin.go` (`openRateLimit`, called between `openOwned` and `claimOwned`; comment "It is never published under an instance name, so it has no alias and no Watch"; `New` comment "rateLimitEnabled = Open the rate-limit counter only; it has no instance name and no Watch"). It is not in `openOwned` / `claimOwned`, so no `ClearPublisher` when the flag drops and no rollback entry.
- Client and ownership key — `pkg/ratelimit/client.go` (`Open(ctx, middlewareName, RedisSettings, log)` → `reclaim.OpenWithHooks(OwnershipKey(middlewareName, settings), …)`; `OwnershipKey` = `ratelimit:owner:` + FNV-64a of JSON `{middlewareName, host, password, database, syncRate}`; `Client` holds the `windowcounter.Limiter`, the `simpleredis` client, an incarnation string, a log). No `Incarnation()` method on the rate-limit Client (the other four Clients have one).
- Lifecycle hooks — `pkg/ratelimit/client.go` (`reclaim.Hooks{Sleep, Wake, Close}`: `Sleep` flushes buffered hits and stops the flush timer, `Wake` restarts it, `Close` is idempotent: last flush, then Redis close; log lines `crowdsec ratelimit instance started|sleeping|waking|closed`).
- Attach — `pkg/bouncer/bouncer.go` (`AttachRateLimit(counter ratelimit.Counter)` sets the plain field `rateLimitCounter` once, before `New` returns the handler; `plugin.go` comment "so no request can race the plain field"). A Watch-fed or atomic counter field — `not found`.
- Bucket compile and per-router policy — `pkg/bouncer/bouncer.go` (`New`: `ratelimit.NewBucketSet(config.RateLimitBuckets)` only when `config.RateLimitEnabled`; `rateLimitFailureAction` via `EffectiveRateLimitFailureAction`, `rateLimitResponseHeaders`, `rateLimitStatusCode` stored per router).
- Counter key — `pkg/bouncer/bouncer_serve_ratelimit.go` (`serveRateLimit` passes `b.name`, the router's own middleware name, to `Charge`) → `pkg/ratelimit/key.go` (`redisCounterKey`: `rl:<middlewareName>:<bucket>:<16 hex of SHA-256>`). Today the owner name and the counter name are the same `name`.
- When a router charges — `pkg/bouncer/bouncer_serve_ratelimit.go` (`serveRateLimit` returns false when `rateLimitCounter` or `rateLimitBuckets` is nil, or `SkipRateLimit`); `pkg/bouncer/bouncer.go` (`ServeHTTP` passes through when `bouncerEnabled` is false, default false, so a `rateLimitEnabled` router without `bouncerEnabled` opens a counter and charges nothing).
- Config fields — `pkg/configuration/configuration.go` (L174–184 `RateLimitBuckets`, `RateLimitEnabled`, `RateLimitFailureAction`, `RateLimitRedisDatabase`, `RateLimitRedisHost`, `RateLimitRedisPassword`, `RateLimitRedisPasswordFile`, `RateLimitResponseHeaders`, `RateLimitStatusCode`, `RateLimitStore`, `RateLimitSyncRate`; defaults L319–328). `RateLimitInstanceName` — `not found` in code.
- Validation — `pkg/configuration/configuration.go` (`ValidateParams` runs `validateRateLimit` only when `RateLimitEnabled`: store, host, password file, sync rate, `rateLimitFailureAction` with `captchaInstanceNameReadyAfterOwnerFill(config)` of the same router, status code, non-empty buckets, `NewBucketSet`).
- Live spec "not published" — `openspec/specs/core_plugin_ratelimit_client/spec.md` (L8: ownership key from the middleware name and Redis settings, "Two routers that use the same middleware SHALL share one counter"; L10: "The counter SHALL NOT be published under an instance name and SHALL NOT be watched by another middleware. Bucket rows, `rateLimitFailureAction`, `rateLimitStatusCode`, and `rateLimitResponseHeaders` SHALL NOT be part of the ownership key; they stay per router.").
- Live validation spec — `openspec/specs/core_plugin_middleware_config-validation/spec.md` (L466–476: `rateLimit*` read only when `rateLimitEnabled`; `rateLimitFailureAction: captcha` needs a captcha instance name after owner-fill).
- Devdocs leg term — `knowledge/devdocs/core_plugin_ratelimit.md` (L6 "Never published under an instance name; no alias, no Watch."; L7 `_Avoid_: rate limiter instance, rateLimitInstanceName, publishing it with SetAlias, …`).
- Devdocs validation term — `knowledge/devdocs/core_plugin_middleware_config-validation.md` (L20–23 `RateLimitEnabled`: "this router opens the rate-limit Client and charges `rateLimitBuckets`"; `_Avoid_: … rateLimitInstanceName`).
- README rate-limit section — `README.md` (L862 "every Traefik replica that runs the same middleware counts into the same total"; L1297 `RateLimitBuckets` reference; no instance-name setting).
- Debt note taken by addendum B — `knowledge/debt/2026-11-20-extract-common-leg-abstraction.md` ("Each published leg (LAPI, AppSec, captcha)", "rewrites the three existing legs"; ModSec is missing although `plugin.go` has four); its row — run `issues.md` (first row, `note large`, Why ends "the Open-only rate-limit leg does not need it").

Tests that pin the current wiring:

- Rate-limit constructor — `zzz_rate_limit_test.go` (`TestNew_RateLimitDisabledOpensNothing`, `TestNew_RateLimitSharesOneCounter` peeks `ratelimit.OwnershipKey` under the router's own name, `TestNew_RateLimitReleasedWhenNewFailsAfterOpen` pins `openRateLimit` before `claimOwned`, `TestNew_RateLimitDeadRedisFailureAction`, `TestNew_RateLimitDeadRedisBufferedKeepsTheLocalLimit`).
- Rate-limit router — `pkg/bouncer/zzz_rate_limit_test.go` (calls `AttachRateLimit` directly, e.g. L97, L380).
- Rate-limit Client — `pkg/ratelimit/zzz_client_test.go` (`TestOpen_sharesOneClientPerMiddlewareAndSettings`, …) and `pkg/ratelimit/zzz_yaegi_test.go` (`TestYaegi_OpenChargeClose`).
- Captcha owner / subscriber — `zzz_constructor_test.go` (`TestNew_CaptchaOwnerOmitFillsTraefikName`, `TestNew_CaptchaSubscriberBeforePublishBans`, `TestNew_CaptchaHolderWithBounceOffStillPublishes`, `TestNew_CaptchaInstanceNameCollisionFails`, …).
- ModSec owner / subscriber and rollback — `zzz_modsec_plugin_test.go` (`TestNew_ModsecSubscriberUsesOwnerClient`, `TestNew_ModsecInstanceNameCollisionFails`, `TestNew_CaptchaClaimFailureClearsModsecPublisher`).
- Receive side — `pkg/bouncer/zzz_servehttp_gaps_test.go` (`TestReceiveLAPI_*`, `TestHandleNextServeHTTP_UnpublishedAppSecUsesFailureAction`); `pkg/bouncer/zzz_store_binding_test.go`.
- Leftover rate-limit settings — `pkg/configuration/zzz_rate_limit_test.go` (`Test_ValidateParams_disabledRateLimitIgnoresLeftovers`).
- Published-leg severance e2e — `tests/e2e/real/instance_severance.Tests.ps1` (greps `"leg":"appsec"` lifecycle logs). Rate-limit e2e — `tests/e2e/real/config/dynamic/rate-limit.yml` (five routers since `410c30ca`, each with its own `rateLimitEnabled` middleware; no owner / subscriber pair).

Limiter-level algorithm (addendum C). Measured on the branch head `a21abe4b` (round 2 implemented and reviewed; utilities pinned at `v1.0.10`). One entry path per claim.

- Where the operator picks the algorithm today — `pkg/ratelimit/bucket_set.go` (`validateAlgorithm`, per bucket: empty or `slidingWindow` passes; `tokenBucket` fails `algorithm: tokenBucket is not supported in this version`; any other value fails `algorithm: must be "slidingWindow"`; any non-zero `burst` fails `burst: is not supported in this version`). A limiter-level setting `rateLimitAlgorithm` — `not found` (`pkg/configuration/configuration.go` L174–185 lists every `RateLimit*` field).
- `algorithm` / `burst` row fields — `pkg/ratelimit/bucket_rule.go` (`BucketRule.Algorithm`, `BucketRule.Burst`; comment "exist only so NewBucketSet can reject values this version does not support, instead of Traefik dropping them silently"; `AlgorithmSlidingWindow` "is the only counting algorithm in this version").
- Counter contract — `pkg/ratelimit/counter.go` (`type Status = windowcounter.Status`; `Counter.Take(ctx, key, limit int64, window) (Status, error)`; the hit "is counted even when it is over the limit").
- Client construction — `pkg/ratelimit/client.go` (`newClient` always builds one `windowcounter.New(redis, settings.SyncRate)` on the `simpleredis` client; `Client.counter` is that limiter or a test fake; `Sleep` / `Wake` / `Close` call the limiter, then `Close` closes Redis).
- Ownership key — `pkg/ratelimit/client.go` (`OwnershipKey` hashes `{buckets, middlewareName, policy, redis}`; no algorithm field).
- Charging and Retry-After — `pkg/ratelimit/charge.go` (`Charge` calls `counter.Take(ctx, key, bucket.requests, bucket.window)` per bucket, "Count, then compare: an answered hit still counts"; `wholeSecondsAtLeastOne` rounds `RetryAfter` up to whole seconds, at least 1s).
- Redis key — `pkg/ratelimit/key.go` (`redisCounterKey`: `rl:<middleware>:<bucket>:<16 hex>`, "The counter appends the window start"); vendored `windowcounter/limiter.go` (`redisWindowKey`: `{opaqueKey}:{windowStartUnix}`). A token-bucket key — `not found`.
- Token bucket in the pinned library — module cache `traefik-middleware-utilities@v1.0.10/tokenbucket/redis.go` (`NewRedis(redis, rate float64, burst int64, maxDelay, ttl)`; `Allow(ctx, key)` is one `simpleredis` `Eval` of `allowScript`); `clock.go` (`validateClock`: rate > 0 and finite, burst >= 1, maxDelay >= 0, ttl a whole number of seconds >= 1s; `consumeOne` refunds the token when the wait exceeds maxDelay); `lua.go` (an empty hash seeds `tokens = burst`; `HSET last tokens` + `EXPIRE ttl` on every call); `status.go` (`Status{Allowed, Limit (= burst), Remaining, Period, Reset, RetryAfter, Delay}`). The `Redis` struct holds only the clock, `now`, and the Redis client (no goroutine, no Close). The library ships Yaegi tests (`tokenbucket/limiter_yaegi_test.go`, `memory_yaegi_test.go`).
- `tokenbucket` in this module — not imported and not vendored (`vendor/modules.txt` lists `backendbackoff`, `iplookup`, `reclaim`, `simpleredis`, `traefikemulator`, `windowcounter`); `go.mod` pins `v1.0.10`. Lint allow-list — `.golangci.yml` (depguard `Main` allows `windowcounter`, not `tokenbucket`).
- Yaegi exposure in CI — `.github/workflows/main.yml` ("Expose utilities on GOPATH for Yaegi" copies `vendor/github.com/david-garcia-garcia/traefik-middleware-utilities` into GOPATH); `pkg/yaegitest/interpreter.go` (`GoPath` links the same vendor tree). Whether the plugin runs `tokenbucket` under Yaegi v0.16.1 — not measured in this repo.
- Specs that reject it today — `openspec/changes/share-rate-limit-leg-and-bucket-actions/specs/core_plugin_ratelimit_buckets/spec.md` ("Bucket algorithm, action, and store values are validated": `algorithm` accepts only `slidingWindow`, `tokenBucket` or `burst` fail); `.../core_plugin_middleware_config-validation/spec.md` (row rules "`algorithm` is set and is not `slidingWindow`; `burst` is set"); live `openspec/specs/core_plugin_ratelimit_client/spec.md` ("Sync rate trades accuracy for Redis round trips", sliding window only).
- Docs that say it is not there — `README.md` L981 ("Only the sliding window on Redis. `algorithm: tokenBucket`, `burst`, and `rateLimitStore: memory` fail at startup"); `knowledge/devdocs/core_plugin_ratelimit.md` (L6 "one vendored `windowcounter.Limiter`", L15 `_Avoid_: ... token bucket`, L105 "`algorithm`, `burst`, and `rateLimitStore` exist only to reject").
- Round-1 debt note — `knowledge/debt/2026-11-20-rate-limit-token-bucket-and-memory-store.md` (`tokenBucket` + `burst` and the memory store in one note; "Unblock: ... vendor `tokenbucket`, then add the algorithm and store (one `tokenbucket` limiter per bucket, since rate and burst are fixed at `New`)"); its run `issues.md` row (`[ ] note large`).
- Real-stack rate-limit fixtures — `tests/e2e/real/config/dynamic/rate-limit.yml` (five routers, sliding window only), `tests/e2e/real/rate_limit.Tests.ps1`.

## Out of scope

Round 2, inferred extras, listed and not taken:

- An alias or deprecation path for `deny` (addendum: rename, no alias).
- New fields for a hard ceiling (addendum: stacking only, "No new fields").
- A new captcha session setting (decision 1: reuse `captchaGracePeriodSeconds`).
- Changing `bypassCaptcha` anywhere outside a `captcha` bucket (decision 2 scopes the different meaning to buckets).
- Changing `rateLimitFailureAction: captcha`, which still fails at startup without a captcha instance name (see `## Tensions`); not asked.
- Exempting CrowdSec AppSec's own challenge traffic (`/crowdsec-internal/challenge/`) from buckets: decision 5 names the captcha page's requests (widget assets, verification POST), not AppSec's challenge.
- The other round-1 debt notes (`tokenBucket` / memory store, Redis backoff gate, windowcounter bump, single-reading-path spec): not reopened. The common leg abstraction note is no longer in this list: addendum B decision 4 takes it.
- Addendum B non-goals (conductor, "Not in this round"): the single-EVAL + local over-limit-cache load design; Redis TLS / ACL user settings on `rateLimitRedis*`; `RateLimit-*` response headers (its round-1 debt note stays open). Each stays a follow-up.
- Counters shared across subscribers (`rl:<instance>:…`): addendum B decision 3 rejects it.
- Per-subscriber overrides of the owner's bucket list or policy: not asked (decision 2 centralizes the policy).
- The leg / instance / backend vocabulary rename (`knowledge/debt/2026-09-23-leg-instance-backend-vocabulary.md`): decision 4 asks for a shared leg unit, not a rename of the existing terms.

Addendum C:

- `rateLimitStore: memory` (conductor proposal: "not asked; per-replica; `tokenbucket.Memory` makes it a small follow-up"); the memory half of the round-1 debt note stays open.
- A per-bucket algorithm (human decision: "no a nivel de bucket sino de todo el limiter").
- Queuing a request instead of answering it (`maxDelay` > 0, Traefik's delayed admit): the proposal fixes `maxDelay` at 0.
- `RateLimit-*` headers from the token bucket's `Limit` / `Remaining` / `Reset`: the round-1 debt note `knowledge/debt/2026-11-20-rate-limit-ratelimit-response-headers.md` stays open.

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

Addendum B (shared rate-limit leg). "B-n" below is addendum B decision n.

- What the owner publishes: the `ratelimit.Client` alone (today only the limiter and the Redis client, `pkg/ratelimit/client.go`) with each subscriber compiling the owner's buckets, or a published value that carries the compiled `BucketSet` and the policy (`rateLimitFailureAction`, `rateLimitStatusCode`, `rateLimitResponseHeaders`). If the policy is published, whether it joins the ownership key (a bucket edit opens a new Client and a new counter generation) or is republished on the same Client.
- What a subscriber does with its own `rateLimit*` settings: ignored as owner-read leftovers (the captcha / ModSec precedent in `validateOpenVsSubscribe`), rejected at startup, or allowed as overrides. The conductor reading of B-2 puts everything on the owner and only the instance name on the subscriber; not confirmed.
- What `rateLimitEnabled` means after B-1 on a router that also has `bouncerEnabled`: own only (conductor assumption) or own + charge here (round-1 meaning). Whether an omitted `rateLimitInstanceName` fills the Traefik name when owned (other legs' `Prepare`), so a round-1 style config (one middleware, `rateLimitEnabled` + `bouncerEnabled`, no instance name) keeps charging through its own alias.
- A subscriber whose owner is not published yet, or whose owner went away: pass through (today `rateLimitCounter == nil` skips the leg), or apply `rateLimitFailureAction`, and whose failure action (owner's or subscriber's). Other legs differ: an unpublished AppSec uses the failure action, an unpublished captcha bans (`pkg/bouncer/zzz_servehttp_gaps_test.go`, `zzz_constructor_test.go`).
- Startup validation of `rateLimitFailureAction: captcha` and of `action: captcha` buckets once the policy lives on the owner but the captcha subscription lives on the subscriber: today `validateRateLimit` checks `captchaInstanceNameReadyAfterOwnerFill` on the router that carries the policy; after B-2 the owner may have no captcha while its subscribers do, and the reverse. Interacts with round-2 decision 3 (runtime downgrade, no startup failure) for buckets.
- "Counters per subscribing router" (B-3) vs the key's unit: `Charge` keys by the middleware name (`b.name`), so two Traefik routers that use the same subscriber middleware share one counter (live spec "Two routers that use the same middleware SHALL share one counter"). Whether "per router" means per subscriber middleware (the conductor's key `rl:<subscribing router middleware name>:…` reads that way) or per Traefik router.
- Shape of the leg descriptor (B-4): which fields (group, `*Enabled`, instance name, `Prepare`, `Open`, ownership key, Watch empty value, receive hook, trace name) and how per-leg extras survive: the LAPI header-scope warning in `receiveLAPI`, `LapiClient` / `SameLapiClient`, AppSec's `Key` (not `OwnershipKey`), and the hand-written rollback order including the spec line "Captcha-claim failure SHALL also `ClearPublisher` ModSec". Whether a generic binding type runs under Yaegi (no generics in the repo today; not measured).
- What proves "behaviour-preserving" for the four legs: existing unit tests plus `tests/e2e/real/instance_severance.Tests.ps1`, or new tests that pin the lifecycle log lines (`crowdsec bouncer bound|unbound` trace attrs, `crowdsec instance name taken`) that the instance-slots spec ("Lifecycle logs match e2e grep contract") makes part of the contract.
- Rate-limit Client identity for bind / unbind traces: it has an incarnation string but no `Incarnation()` method (`pkg/ratelimit/client.go`); whether it gains one to fit the shared binding.
- How the debt note's "three legs" error and its row's "the Open-only rate-limit leg does not need it" are corrected: the row cannot be deleted (`opd-workflow § Issues`), so implement marks it `[x]` with a `Taken:` line and deletes the debt file; whether anything else (card summary) needs the four-leg correction.
- E2E for the shared leg: an owner and two subscribers on the Dragonfly stack proving one policy and separate budgets (B-2, B-3), and severance when the owner is removed.

Addendum C (limiter-level algorithm). The conductor's proposal answers most of these; explore records each as an open question.

- Whether `tokenbucket.Redis` runs under Yaegi v0.16.1 inside this plugin (vendored, GOPATH layout); the library's own Yaegi tests pass upstream, not measured here.
- The plugin-owned status Charge needs once `ratelimit.Status` can no longer alias `windowcounter.Status`, and how one `Counter` serves both libraries (the token bucket has no `limit` / `window` arguments: rate and burst are fixed at `NewRedis`).
- `burst` default, bounds, and meaning under `slidingWindow` (proposal: default `requests`, only with `tokenBucket`).
- TTL of the token-bucket hash ("a TTL that covers a full refill"): exact value, and what a full refill longer than a TTL Redis or Dragonfly accepts does.
- The distinguishing suffix that keeps a token-bucket hash from colliding with a sliding-window string of the same bucket after an algorithm switch.
- What a denied hit does to the count under each algorithm: the sliding window counts it (`windowcounter` increments before comparing), the token bucket with `maxDelay` 0 refunds it (`consumeOne`). The live scenario "A denied client stays limited while it keeps sending" assumes the first.
- A Redis outage under `tokenBucket`: no buffered mode exists, so every take is one `EVAL`; whether the failure action then applies as in exact mode.
- Whether `rateLimitSyncRate` stays in the ownership key under `tokenBucket`, where nothing reads it.
- Real-stack proof: burst requests admitted at once, the next one 429 with a `Retry-After` matching the refill; and whether the Pester harness can assert a startup failure for a bucket `algorithm:`.

## Tensions

- Decision 5 ("never counted or blocked by any bucket") vs decision 2's rationale ("a rate limit must not become unlimited"): a client that always sends the challenge marker, or only fetches widget assets, is never limited by any bucket, and each verification POST costs a call to the captcha provider.
- Decision 3 (runtime downgrade + ERROR, no startup failure) vs `rateLimitFailureAction: captcha`, which fails `ValidateParams` without a captcha instance name (`pkg/configuration/configuration.go`): two behaviours for "captcha on a router without a captcha" in the same leg.
- Decision 3 "log an ERROR" vs the owner's rule for gates "log on transitions, never per request" (cited in the addendum) and the existing per-request WARN on an unsubscribed downgrade (`pkg/bouncer/bouncer_serve_captcha.go`).
- Decision 3 "use the existing downgrade path" vs that path's answer: `bouncerRemediationStatusCode` (403 by default), no `Retry-After`, header `ban:captcha-downgrade` without the bucket, while a rate-limit bucket answers `rateLimitStatusCode` (429) + `Retry-After` + `ban:ratelimit:<bucket>`.
- Decision 2 (`bypassCaptcha` on a `captcha` bucket → 429) vs every current `bypassCaptcha` consumer, including the leg's own `captchaRateLimitFailure`, which lets the request through (`pkg/bouncer/bouncer_serve_ratelimit.go`). The human chose the difference on purpose; the failure-action path keeps the old meaning.
- Decision 4 accepts what the round-1 debt note warned about (`knowledge/debt/2026-11-20-rate-limit-captcha-action.md`): a bot that solved one captcha is exempt from `captcha` buckets for `captchaGracePeriodSeconds` (default 86400s). The addendum's answer is stacking a `ratelimit` bucket; nothing enforces that a `captcha` bucket has one.
- Rename vs synced specs: round 1's archived and synced specs, README, devdocs, and e2e all say `deny` (see `## Current (code)`); the rename touches live `openspec/specs/*` that round 1 just wrote, plus the devdocs `_Avoid_` term "per-bucket captcha".
- Header vocabulary: the round-1 caller spec (semantics 7) and the addendum table name `captcha:ratelimit:<bucket>`, but no README, live spec, or devdoc lists it (`grep` finds none); it is a new value in the closed table of `openspec/specs/core_plugin_middleware_bouncer/spec.md` and `README.md` (L697 area).

Addendum B (shared rate-limit leg):

- B-1 (publish the leg) vs round-1 artifacts that say the opposite and were just synced: `openspec/specs/core_plugin_ratelimit_client/spec.md` L10 ("SHALL NOT be published … SHALL NOT be watched"), `knowledge/devdocs/core_plugin_ratelimit.md` L6–7 ("Never published"; `_Avoid_: rateLimitInstanceName, publishing it with SetAlias`), `knowledge/devdocs/core_plugin_middleware_config-validation.md` L23 (`_Avoid_: rateLimitInstanceName`), the `plugin.go` comments on `New` and `openRateLimit`, the README connection table (four legs), and the round-1 `## Out of scope — round 1` row "Publishing the rate limit leg as a shared instance … not asked". The human reversed that row; the artifacts must follow.
- B-2 (policy centralized on the owner; conductor reading: failure action, status code, response headers too) vs the live spec ("Bucket rows, `rateLimitFailureAction`, `rateLimitStatusCode`, and `rateLimitResponseHeaders` … stay per router") and the README owner / subscriber rule for every other leg ("A middleware that only protects … keeps its own request settings (status code, captcha, …, behavior when CrowdSec or a WAF is down, response headers)"). The rate-limit leg would be the first leg whose request-time answers live on the owner.
- B-3 (counters keyed by the subscriber's name) vs the ownership key (owner's name): today both are the same `name` (`plugin.go` `openRateLimit`, `pkg/bouncer/bouncer_serve_ratelimit.go`); after B-1 the Client is keyed by the owner and the counters by each subscriber, so the code must stop assuming they match. Also "per router" in B-3 vs the per-middleware key (see `## Unknowns`).
- Captcha on the owner's buckets vs captcha on the subscriber: the conductor assumption decides the captcha-bucket behaviour (downgrade, `bypassCaptcha`, gate check) on the subscribing router, but the `captcha` action lives in the owner's bucket list and `validateRateLimit` checks captcha readiness on the router that carries the policy.
- `rateLimitEnabled` = own (conductor assumption) vs its round-1 meaning "this router opens the rate-limit Client and charges `rateLimitBuckets`" (`knowledge/devdocs/core_plugin_middleware_config-validation.md`, `bouncer.New` compiling buckets only on `RateLimitEnabled`). Unreleased (PR #228 unmerged), so no user break, but the live spec and devdocs change meaning.
- B-4 (extract the abstraction in this PR) vs the debt note's reason for not taking it ("a refactor of shipped wiring with no rate-limit criterion behind it") and PR size: one PR now carries the round-1 leg, the round-2 bucket actions, a refactor of four shipped legs (LAPI, AppSec, captcha, ModSec, all on `master`), and the shared leg. The human approved it and asked for a separate behaviour-preserving commit first, with existing tests green.
- B-4 vs the debt note's text: it names three legs (LAPI, AppSec, captcha) and three `bouncer_leg_*.go` files; the code has four (`bouncer_leg_modsec.go`, `legModsec`). The addendum flags it; the descriptor must cover ModSec's place in the rollback order.
- Round-2 `## Out of scope` (as first written) said the common leg abstraction note was "not reopened"; B-4 reverses it (removed from that list in this update).

Addendum C (limiter-level algorithm):

- Human decision (the algorithm belongs to the limiter) vs the per-bucket `algorithm` row field that round 1 shipped and round 2 kept to reject `tokenBucket` (`pkg/ratelimit/bucket_rule.go`, the `core_plugin_ratelimit_buckets` and `core_plugin_middleware_config-validation` deltas). Unreleased (PR #228 unmerged), so removing it breaks no user; the row field must still exist so Traefik does not drop it silently.
- Conductor correction vs earlier records: the round-1 debt note and the round-2 grounding say `tokenBucket` waits on an upstream fix; utilities PR #54 is in `v1.0.9`, and this branch pins `v1.0.10`. The note's tokenBucket half is taken by this addendum; its memory half is not.
- Same `requests` / `window` words, two meanings: a sliding-window bucket admits `requests` per rolling `window`; a token bucket refills at `requests / window` per second and admits up to `burst` at once. With the default `burst = requests` a client that waited a full window can send `requests` at once under both, but a token bucket also admits steady traffic at the refill rate after a deny, while the sliding window keeps counting denied hits.
- `rateLimitSyncRate` default `200ms` vs `tokenBucket`, which never reads it (proposal: documented, not rejected).
