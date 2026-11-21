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
