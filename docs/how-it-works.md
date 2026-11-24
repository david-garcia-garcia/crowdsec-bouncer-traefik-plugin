[Documentation](README.md) › How the middleware works

# How the middleware works

The base concepts of the plugin: what a leg is, which middleware holds each connection, what stays on each router, and in which order a request is checked. What each leg does when its backend fails is on its own page: [When a dependency is down](failure-modes.md).

- [Legs](#legs)
- [The middleware that connects and the routers that use it](#the-middleware-that-connects-and-the-routers-that-use-it)
- [What lives where](#what-lives-where)
- [Connections across reloads](#connections-across-reloads)
- [Order of the checks](#order-of-the-checks)
- [The request body](#the-request-body)

## Legs

A **leg** is one check that needs something outside Traefik: a CrowdSec service, a sidecar, or Redis. The plugin has five:

| Leg | What it checks | Backend | Page |
| --- | -------------- | ------- | ---- |
| LAPI | CrowdSec decisions for the client IP, a range that contains it, or a mapped header scope (country, AS, …) | CrowdSec LAPI, or CAPI in `alone` mode, plus an optional Redis cache | [Concepts › Decisions](concepts.md#decisions), [LAPI modes](concepts.md#lapi-modes) |
| Rate limit | How many requests a client, a token or a tenant sent to the route | Redis | [Rate limit](rate-limit.md) |
| AppSec | The request itself, with CrowdSec's WAF | CrowdSec AppSec | [Concepts › AppSec](concepts.md#appsec) |
| ModSec | The request itself, with OWASP CRS | A ModSecurity CRS sidecar | [ModSecurity (OWASP CRS)](modsecurity.md) |
| Captcha | Whether the visitor solved a captcha | The captcha provider (hCaptcha, Turnstile, …) | [Concepts › Remediation](concepts.md#remediation) |

The captcha is not a step of its own. It is how the other legs, and `captcha` action rules, serve a captcha: a CrowdSec captcha decision, a `captcha` rate-limit bucket, an AppSec `captcha` answer, or a failure action set to `captcha`.

Everything that needs no backend runs on the router itself, without a leg: reading the client IP, trusted IPs, [`bouncerActionRules`](configuration.md#bounceractionrules), the ban page, the status code, and the response headers.

## The middleware that connects and the routers that use it

Each leg has two switches, and they are independent:

| Leg | Connect and share | Use on this router |
| --- | ----------------- | ------------------ |
| LAPI | `lapiEnabled: true` | `bouncerEnabled: true` and `lapiInstanceName` |
| Rate limit | `rateLimitEnabled: true` | `bouncerEnabled: true` and `rateLimitInstanceName` |
| AppSec | `appsecEnabled: true` | `bouncerEnabled: true` and `appsecInstanceName` |
| ModSec | `modsecEnabled: true` | `bouncerEnabled: true` and `modsecInstanceName` |
| Captcha | `captchaEnabled: true` | `bouncerEnabled: true` and `captchaInstanceName` |

- **Connect.** A middleware with `*Enabled: true` opens the connection once and shares it under `*InstanceName`. The name defaults to the middleware's own name, so a single middleware that connects and protects needs no names at all.
- **Use.** A middleware with `bouncerEnabled: true` checks the requests of its router with the connections it names. It does not repeat the host, the key or the interval.
- **Both.** One middleware can connect and protect its own router, as in the [all-in-one setup](middleware-architecture.md#one-middleware-all-in-one).
- **Only connect.** With `bouncerEnabled: false`, the middleware lets every request of its router through, and still shares its connections. Hold such connections on a router of their own: see [Connections on a router with no backend](middleware-architecture.md#connections-on-a-router-with-no-backend).

Names are per leg: the LAPI, rate-limit, AppSec, ModSec and captcha connections can all be called `shared` without conflict. Two middlewares that share the same leg under the same name conflict: the first one loaded keeps the name, and the second one fails to load with the ERROR log `crowdsec instance name taken` (with `leg` and `instanceName`).

On a router, a leg runs only when the router names it:

| On the router | What happens to that leg |
| ------------- | ------------------------ |
| No instance name for the leg, and the middleware does not connect it | The leg does not run on this router. |
| A name some loaded middleware shares | The leg runs with that connection. |
| A name no loaded middleware shares (a typo, an owner not loaded yet, an owner removed) | The leg runs without a connection: LAPI, AppSec and ModSec apply their failure action, the captcha becomes a ban, the rate limit lets the request through. See [The connection is not there](failure-modes.md#the-connection-is-not-there). |

The full set of topologies (one middleware, shared connections, several CrowdSec engines, AppSec only) is in [Middleware architecture](middleware-architecture.md).

## What lives where

Settings of a connection live on the middleware that connects. Settings that decide what happens to a request live on each router, even when the connection is shared, so two routers on the same connection can behave differently.

| Leg | On the middleware that connects | On each router that uses it |
| --- | ------------------------------- | --------------------------- |
| LAPI | `lapiHost`, `lapiKey`, `lapiMode`, intervals, TLS, `lapiStreamScopes`, the CAPI credentials of `alone`, the [Redis cache](configuration.md#redis-cache), `lapiUnhealthyBackOffPeriodSecs` (and the backoff state, `live` and `none`) | `bouncerLapiFailureAction`, `bouncerLapiBackOffAction`, `bouncerLapiRedisFailureAction`, `bouncerDecisionScopeHeaders`, `bouncerOriginBasedDecisionRemap`, and `lapiDefaultDecisionSeconds` for the answers this router caches in `live` mode |
| Rate limit | Redis, and the **whole policy**: `rateLimitBuckets`, `rateLimitAlgorithm`, `rateLimitStatusCode`, `rateLimitResponseHeaders`, `rateLimitFailureAction`, `rateLimitSyncRate` | Nothing but the name: each router counts under its own middleware name, and serves its own captcha |
| AppSec | `appsecHost`, `appsecKey`, timeout, `appsecBodyLimit`, TLS, `appsecUnhealthyBackOffPeriodSecs` (and the backoff state) | `bouncerAppsecFailureAction`, `bouncerAppsecBackOffAction` |
| ModSec | `modsecUrl`, timeout, `modsecBodyLimit`, `modsecUnhealthyBackOffPeriodSecs` (and the backoff state) | `bouncerModsecFailureAction`, `bouncerModsecBackOffAction` |
| Captcha | Provider, keys, template, `captchaGracePeriodSeconds`, `captchaGateSecret`, `captchaGateBindIp`, the siteverify timeout | Whether this router has a captcha at all |

On every router, whatever it connects: `bouncerEnabled`, `bouncerActionRules`, `bouncerClientTrustedIps`, the forwarded-header settings, `bouncerBanFilePath`, `bouncerRemediationStatusCode`, `bouncerRemediationHeadersCustomName`, `bouncerTraceHeadersCustomName`.

The rate limit is the exception to the rule: its failure action, status code and buckets are the policy, so they live on the middleware that connects. A router that uses the policy does not read its own `rateLimit*` settings.

## Connections across reloads

Traefik builds every middleware again on each configuration reload. The plugin keeps connections across reloads so that a reload does not reconnect to CrowdSec, drop the LAPI decisions in memory, or reset a backoff gate.

- **Nothing changed in the connection settings.** The same connection is reused. Renaming only `*InstanceName` keeps it too.
- **A connection setting changed** (host, key, mode, timeout, body limit, backoff cooldown, buckets, Redis settings, …). A new connection opens, and the routers that use the name switch to it at once. The old one closes after [`reclaimGraceSeconds`](configuration.md#reclaimgraceseconds) (default 30). A new connection starts fresh: a new LAPI stream, a closed backoff gate. Changing only a router's failure or backoff action does not open a new connection.
- **The middleware that connects is gone from the configuration.** Routers keep using its last connection until `reclaimGraceSeconds` runs out, then the leg has no connection (see the table above). During that time a LAPI connection still answers from the decisions it holds, but no longer refreshes them.
- **The middleware is still there, with `*Enabled: false`.** Routers lose the connection at once.
- **Right after Traefik starts or reloads**, a router can take requests before the middleware that connects is loaded, for example when the two come from different providers. Those requests are handled as if the connection were missing. [Connections on a router with no backend](middleware-architecture.md#connections-on-a-router-with-no-backend) shows how to keep that window short.

`reclaimGraceSeconds` is read once per Traefik process: the first value loaded applies.

## Order of the checks

On each request the middleware runs these steps in order. The first step that answers (ban page, captcha page, 429, or an error status) ends the request: later steps do not run and your application is not called.

1. **Client IP.** The address comes from the [trusted proxy settings](how-to/behind-proxy.md). If it cannot be read, the answer is HTTP 502. An address in [`bouncerClientTrustedIps`](how-to/trusted-ips.md) goes straight to your application: none of the steps below run.
2. **`ban` action rule.** A matching [`bouncerActionRules`](configuration.md#bounceractionrules) row with `ban` answers here, before CrowdSec is asked.
3. **LAPI decision.** A ban or captcha decision for the client IP, a range that contains it, or a mapped header scope.
4. **Rate limit.** The buckets of the [rate limit](rate-limit.md). A client that step 3 already banned or challenged is not counted.
5. **AppSec, then the captcha of a `captcha` action rule.** With a `captcha` rule, AppSec is asked first; when it lets the request through, the client gets the captcha page, or goes on if it already solved one.
6. **ModSecurity sidecar.** See [ModSecurity (OWASP CRS)](modsecurity.md).
7. **Your application.**

Steps 1 and 2 need no backend. Steps 3 to 6 are the [legs](#legs); each one that cannot reach its backend handles that on its own, as described in [When a dependency is down](failure-modes.md).

A step the router does not use (no LAPI, rate-limit, AppSec, or ModSec instance name) is skipped. Action rules skip single steps:

| Action | LAPI | Rate limit | AppSec | ModSec |
| ------ | ---- | ---------- | ------ | ------ |
| `bypass` | skipped | runs | skipped | skipped |
| `bypassLapi` | skipped | runs | runs | runs |
| `bypassRateLimit` | runs | skipped | runs | runs |
| `bypassAppsec` | runs | runs | skipped | runs |
| `bypassModsec` | runs | runs | runs | skipped |

Under `/crowdsec-internal/challenge/` a `bypass` or `bypassAppsec` rule does not skip AppSec (see [AppSec](concepts.md#appsec)). A rule with a `path` skips nothing when the request path can be read more than one way (see [BouncerActionRules](configuration.md#bounceractionrules)).

## The request body

AppSec and ModSec read the request body, once between them; the rate limit only peeks at it:

- **AppSec** reads the body of POST, PUT, PATCH and DELETE requests and sends at most [`appsecBodyLimit`](configuration.md#appsecbodylimit) bytes of it (10 MB by default).
- **ModSec** holds the whole body in memory up to [`modsecBodyLimit`](configuration.md#modsecbodylimit) (8 MiB by default) and answers HTTP 413 above it. When AppSec already read the whole body, ModSec reuses those bytes.
- **The rate limit** looks at the first 64 KiB of a body only to recognise a posted captcha form, and only when it may answer with a captcha (see [Rate limit](rate-limit.md)).

Your application receives the same bytes, whole, whatever the limits. A client that disconnects while its body is read gets nothing and the verdict header `error:client-disconnected`; a body that cannot be read while the client is still there gets HTTP 400 and `error:client-body-read`. Neither is a ban, and neither applies a failure action. A POST, PUT or PATCH body streamed over HTTP/2 or HTTP/3 without a length is never buffered: see [What AppSec and ModSec count as a failure](failure-modes.md#what-appsec-and-modsec-count-as-a-failure).
