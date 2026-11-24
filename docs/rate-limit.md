[Documentation](README.md) › Rate limit

# Limit how often a client calls a route

The rate limit caps how many requests a client, a token, or a tenant sends to a route. Counters live in Redis, so every Traefik replica that runs the same middleware counts into the same total. It is off unless a middleware sets `rateLimitEnabled: true`.

One middleware with `rateLimitEnabled: true` and `bouncerEnabled: true` holds the policy and applies it to its own router:

```yaml
rateLimitEnabled: true
rateLimitRedisHost: redis:6379
rateLimitBuckets:
  - name: login
    method: "^POST$"
    path: "^/login$"
    requests: 5
    window: 1m
    key:
      - from: ip
  - name: per-tenant
    path: "^/t/"
    requests: 300
    window: 1m
    key:
      - from: path
        pattern: "^/t/([^/]+)/"
  - name: per-network
    requests: 1000
    window: 1m
    action: log
    key:
      - from: ip
        ipv4Prefix: 24
        ipv6Prefix: 64
```

**One policy for several routers.** The middleware with `rateLimitEnabled: true` opens the Redis connection and holds the whole policy: `rateLimitAlgorithm`, `rateLimitBuckets`, `rateLimitStatusCode`, `rateLimitResponseHeaders`, `rateLimitFailureAction`, and the Redis settings. It shares it as `rateLimitInstanceName` (default: its own name) and does not need `bouncerEnabled`. A router applies that policy with `bouncerEnabled: true` and the same `rateLimitInstanceName`; its own `rateLimit*` settings are not read. Attach the middleware that holds the policy to a router, as for any connection; with `bouncerEnabled: false` it lets every request of that router through.

```yaml
http:
  middlewares:
    rate-limit-policy:
      plugin:
        bouncer:
          rateLimitEnabled: true
          rateLimitInstanceName: shared
          rateLimitRedisHost: redis:6379
          rateLimitBuckets:
            - name: per-ip
              requests: 100
              window: 1m
              key:
                - from: ip
    api:
      plugin:
        bouncer:
          bouncerEnabled: true
          rateLimitInstanceName: shared
    admin:
      plugin:
        bouncer:
          bouncerEnabled: true
          rateLimitInstanceName: shared
```

**Counters per router.** Each middleware that applies the policy counts under its own name: a client that used its 100 requests through `api` still has 100 through `admin`. Routers that must share one budget use the same middleware.

**When the policy is not loaded.** A router whose `rateLimitInstanceName` no loaded middleware shares (removed, `rateLimitEnabled` turned off, or not loaded yet after a reload) lets every request through: nothing is counted and no verdict header is set. The router logs WARN `crowdsec bouncer rate limit owner unavailable` (with `instanceName`) once when it loses the policy, and INFO `crowdsec bouncer rate limit owner available` once when it gets one back. Traefik rebuilds routers on every reload; the WARN belongs to the middleware name (`traefikName`), not to one build, so a rebuild while the policy is still missing does not repeat it, and the INFO comes from whichever build of that name gets the policy back first, also one Traefik builds after the policy returns. If `rateLimitInstanceName` changes in between, the INFO names the new instance. A router that Traefik builds while no middleware shares the policy yet (at startup, or on a reload that builds it before the owner) logs both lines at once. A change to the buckets, the status code, the `Retry-After` switch, the failure action, the algorithm, or the Redis settings opens a new connection; counts already in Redis are kept for every bucket whose name did not change, and a renamed bucket starts from zero. A change of `rateLimitAlgorithm` starts every bucket from zero: the two algorithms keep separate Redis keys. Renaming `rateLimitInstanceName` keeps the connection.

**Where it runs.** After the CrowdSec decision lookup and before AppSec, ModSecurity, and the captcha of a `captcha` rule (see [Order of the checks](how-it-works.md#order-of-the-checks)). A client that CrowdSec already bans or challenges gets that answer and is not counted. A request answered by the rate limit never reaches AppSec or ModSecurity. Clients in `bouncerClientTrustedIps` and requests banned by a `ban` rule are not counted either.

**Which requests a bucket counts.** The same conditions as a [`bouncerActionRules`](configuration.md#bounceractionrules) rule, written on the bucket: `method`, `path`, `host`, `headers`, `cookies`. A bucket with none counts every request.

**What each counter is per.** `key` is a list of parts joined into one counter key:

| `from` | Value |
| ------ | ----- |
| `ip` | The client IP, the one the [trusted proxy settings](how-to/behind-proxy.md) resolve. `ipv4Prefix` (1–32) and `ipv6Prefix` (1–128) count a whole network instead. |
| `header`, `cookie`, `query` | The value of the header, cookie, or query parameter named by `name`. Header names ignore case; cookie and query names do not. |
| `host` | The host name of the request, without the port. |
| `path` | The request path. |
| `method` | The request method. |

`pattern` (a regular expression with a capture group) keeps only group 1 of the value. An empty `key` gives the whole bucket one counter. When a part has no value (no such header, no match), the bucket is skipped for that request.

**What a bucket does over its limit.** `action` is `ratelimit` (default: the answer below), `captcha` (the router's captcha, see below), or `log` (only logs INFO `crowdsec bouncer rate limit exceeded`, which lets you try a limit before enforcing it). The earlier value `deny` is now `ratelimit`, and `deny` fails at startup.

**Order.** Buckets are checked in list order and every matching bucket counts the request. A `ratelimit` bucket over its limit answers at once, and later buckets are not counted. A `captcha` bucket over its limit does not stop the check: a `ratelimit` bucket over its limit anywhere in the list wins over it. `final: true` stops after that bucket. With the sliding window a request over the limit still counts, so a client that keeps sending stays limited; with the token bucket it takes no token (see below).

**How a bucket counts: `rateLimitAlgorithm`.** The middleware with `rateLimitEnabled` chooses one algorithm for all its buckets; every router that applies its policy counts with it.

| `rateLimitAlgorithm` | `requests` / `window` | Bursts | A request over the limit |
| -------------------- | --------------------- | ------ | ------------------------ |
| `slidingWindow` (default) | At most `requests` in any rolling `window` (the previous window weighs in proportionally). | Up to `requests` at once, if the client sent nothing in the last `window`. | Still counts: a client that keeps sending stays limited until it slows down. |
| `tokenBucket` | Refill rate: `requests` tokens per `window` (`requests: 60`, `window: 1m` is one token a second). | Up to `burst` at once (default `requests`); each request takes one token. | Takes no token: the client gets in again as soon as one token is back, so it is held to the refill rate. |

```yaml
rateLimitEnabled: true
rateLimitAlgorithm: tokenBucket
rateLimitRedisHost: redis:6379
rateLimitBuckets:
  - name: per-ip
    requests: 10      # one token every 6 seconds
    window: 1m
    burst: 30         # up to 30 requests at once after a quiet period
    key:
      - from: ip
```

`burst` (at least 1) is read only with `tokenBucket`; on a `slidingWindow` policy it fails at startup. A bucket whose full refill (`burst` × `window` / `requests`) is longer than 8760h fails at startup. `algorithm` is not a bucket setting: a bucket that sets it fails at startup with a message that points to `rateLimitAlgorithm`. With `tokenBucket`, `rateLimitSyncRate` is not read: every counted bucket is one Redis call before the answer. A bucket's token state lives in Redis under `rl:<middleware>:<bucket>:<hash>:tb` and expires after one full refill.

**Captcha before a hard limit.** Stack a `captcha` bucket and a `ratelimit` bucket on the same key:

```yaml
rateLimitBuckets:
  - name: per-ip-soft
    requests: 60
    window: 1m
    action: captcha
    key:
      - from: ip
  - name: per-ip-hard
    requests: 300
    window: 1m
    key:
      - from: ip
```

Over 60 requests a minute, the client gets this router's captcha page with the verdict header `captcha:ratelimit:per-ip-soft` and no `Retry-After`. Over 300 it gets the `ratelimit` answer of `per-ip-hard`. Once the client solved the captcha, `captcha` buckets stop counting it for `captchaGracePeriodSeconds` (default 24 hours): only a `ratelimit` bucket on the same key still bounds it, so always add one. Nothing checks that you did.

The captcha is the router's own (`captchaEnabled` or `captchaInstanceName` on the middleware that applies the policy). A router without a usable captcha, and a request that a [`bypassCaptcha`](how-to/captcha-off-api-routes.md) rule matches, get the `ratelimit` answer of the `captcha` bucket instead (`rateLimitStatusCode`, `Retry-After`, `ban:ratelimit:<bucket>`), so the limit still holds. A router without a captcha logs ERROR `crowdsec bouncer rate limit captcha unavailable` (`reason` `unsubscribed`) once each time it loads a policy with a `captcha` bucket or `rateLimitFailureAction: captcha`; a router whose captcha is not available logs it with `reason` `unusable` at most every 5 seconds.

The captcha page's own requests are not counted while the router has a usable captcha: the widget files of the `custom` provider, and the posted captcha form (the field `crowdsec_captcha_challenge=v1`, which the stock page sends) when this router's captcha checks it for the rate limit. That is when the policy can answer with a captcha (a `captcha` bucket or `rateLimitFailureAction: captcha`) and no `bypassCaptcha` rule matches the request: a right answer is redirected back with the captcha cookie, a wrong one gets the captcha page again (`captcha:ratelimit`). Otherwise the form post is counted like any other request, so adding that field to a form does not skip the limit. A client that keeps posting that field to a router whose captcha checks it is never limited, and each post costs one call to the captcha provider. A custom captcha page without that field gets its form post counted.

**The `ratelimit` answer.** HTTP `rateLimitStatusCode` (default 429) with the ban page, `Retry-After`, and the verdict header `ban:ratelimit:<bucket>`. `Retry-After` is the number of seconds, rounded up and at least 1, until the counter would admit one more request from that client, if it sends nothing else meantime. With the sliding window it takes the previous window's weight into account, so it can be later than the end of the current window, and requests sent before then get the same answer and still count, which pushes the time further out. With the token bucket it is the time until one token is back (`window` / `requests` from an empty bucket), and requests sent before then do not change it. The answer is reported to CrowdSec as a drop under `plugin:ratelimit:<bucket>`; the captcha page of a `captcha` bucket is a captcha drop under the same origin. `bypassRateLimit` in a [`bouncerActionRules`](configuration.md#bounceractionrules) rule exempts matching requests, for example a health check. `bypass` does not skip the rate limit.

**When Redis is down.** What happens depends on whether the counter asks Redis before it answers:

| Policy | While Redis is down | Answer | Backoff gate |
| ------ | ------------------- | ------ | ------------ |
| `slidingWindow` with the default buffered `rateLimitSyncRate: 200ms` | Each replica keeps counting in its own memory | The bucket's usual answer, on this replica's count | None |
| `slidingWindow` with `rateLimitSyncRate: 0` | Each counted bucket asks Redis first, and fails | `rateLimitFailureAction`, then `rateLimitBackOffAction` once the gate trips | Yes |
| `tokenBucket` | Each counted bucket asks Redis first, and fails | `rateLimitFailureAction`, then `rateLimitBackOffAction` once the gate trips | Yes |

*Buffered sliding window: the limit becomes per replica.* This mode keeps limiting through a Redis outage instead of failing open or closed:

- The limit holds per Traefik replica, not across replicas. With N replicas behind a load balancer, a client spread over them can get up to N times the limit until Redis answers again.
- A client this replica has not counted yet in the current window starts from zero here, even when other replicas counted it in Redis before the outage.
- The hits counted during the outage stay in memory and are written to Redis by the first sync that succeeds, so the shared count catches up when Redis is back. Hits of a window that ended meanwhile no longer count.
- After a failure the replica does not call Redis for one sync interval, then tries again: the background sync, and the next request that needs to read a counter. Against a Redis that does not answer (rather than one that refuses the connection), that request waits up to 250ms.
- `rateLimitFailureAction` and `rateLimitBackOffAction` do not apply, except to a bucket reached after the 250ms the rate limit may spend on Redis for one request. A policy that sets either of them to `ban` or `captcha` logs WARN `crowdsec ratelimit failure action does not apply to a redis outage` once at load, and still loads.
- There is no backoff gate. A gate skips the counter altogether, so a gate that tripped would replace this per-replica limit with the backoff action, by default no limit at all. The counter also almost never returns an error in this mode, so a gate would not see the outage.
- The plugin logs nothing while each replica counts locally: monitor that Redis directly.
- Use `rateLimitSyncRate: 0` or `rateLimitAlgorithm: tokenBucket` when the limit must stay shared across replicas, or when an outage must fail closed.

*Exact sliding window and token bucket: the failure action, then the backoff gate.*

- Each counted bucket asks Redis before it answers. The rate limit of one request waits for Redis 250ms at most, all buckets together.
- A Redis error applies [`rateLimitFailureAction`](configuration.md#ratelimitfailureaction): `passthrough` (default), `ban` (`ban:ratelimit-failure`), or `captcha` (`captcha:ratelimit-failure`, the router's captcha; a router without one serves the ban page with `bouncerRemediationStatusCode` and `ban:captcha-downgrade`).
- After 5 failures in a row, the backoff gate stops calling Redis for [`rateLimitUnhealthyBackOffPeriodSecs`](configuration.md#ratelimitunhealthybackoffperiodsecs) (default 10), and [`rateLimitBackOffAction`](configuration.md#ratelimitbackoffaction) answers instead: `passthrough` (default), `ban` (`ban:ratelimit-backoff`), or `captcha` (`captcha:ratelimit-backoff`). Then one request probes Redis; a probe that gets an answer ends the backoff. So only the first failures wait up to 250ms. `rateLimitUnhealthyBackOffPeriodSecs: 0` turns the gate off: every counted request asks Redis and gets `rateLimitFailureAction`.
- There is one gate per middleware with `rateLimitEnabled`, shared by every router that applies the policy.
- With the defaults both actions are `passthrough`. With `rateLimitFailureAction: ban` (or `captcha`) and the default backoff action, an outage is closed for the first failures and open during each cooldown, and the middleware logs WARN `crowdsec bouncer backoff action laxer than failure action` once at load. To keep the outage closed, set `rateLimitBackOffAction` to the same value, or set the cooldown to `0`. A backoff action stricter than the failure action logs WARN `crowdsec bouncer backoff action stricter than failure action`, as the other gated legs do.
- A Redis that rejects the password does not trip the gate: Redis answered, so it is a setting to fix, and `rateLimitFailureAction` keeps answering every request.

*Logs.* Every Redis error that reaches the plugin logs ERROR `crowdsec ratelimit redis unavailable`, with the `host` and the `error`, at most every 5 seconds. The gate logs WARN `crowdsec ratelimit backoff started` when it trips and INFO `crowdsec ratelimit backoff ended` when a probe succeeds. See [How you notice an outage](failure-modes.md#how-you-notice-an-outage).

**Accuracy across replicas.** The token bucket is exact across replicas: one Redis call per counted bucket, one bucket after another. For the sliding window, with the default `rateLimitSyncRate: 200ms`, each replica counts locally and writes to Redis every 200ms, reading a counter from Redis the first time it sees it in a window. A replica can then admit more than the limit by the hits the other replicas have not written yet. `rateLimitSyncRate: 0` sends every hit to Redis before answering: exact counts, two Redis round trips per counted bucket, one bucket after another.

**Limits of this version.**

- Only Redis: `rateLimitStore: memory` fails at startup. No `RateLimit-*` headers are sent. A request that would wait for a token is answered at once, never queued.
- A `path` condition is matched on the path Traefik passes to the plugin, as for `ban` and `captcha` rules: an encoded path can miss it (see [Keep captchas off API routes](how-to/captcha-off-api-routes.md), "How the path is matched"). An encoded path can also match a `final` bucket with a `path` condition and so skip the buckets after it, including buckets without `path`.
- Header, cookie, and query values come from the client. A key on them limits that value, not the client: a client that changes the value gets a new counter. They also create one Redis key per distinct value; prefer sources with few values.
- The bucket list has been tested with Traefik's file provider. Docker labels and the Kubernetes CRD may not carry a list of objects with a nested list.

All rate-limit settings are in [Configuration › Rate limit](configuration.md#rate-limit).
