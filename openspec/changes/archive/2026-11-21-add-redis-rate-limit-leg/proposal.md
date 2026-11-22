## Why

The plugin answers CrowdSec decisions (LAPI) and request inspection (AppSec), but it cannot cap how often one client, token, or tenant hits a route. Traefik's own `rateLimit` middleware can share its counters through Redis, but each middleware counts on one source (the client address, one request header, or the host) and has no named buckets. The owner wants this plugin to be the single edge WAF, with a limit that is shared across Traefik replicas through Redis and with named buckets that pick which requests count and what each counter is per.

## What Changes

- New rate-limit leg, off by default (`rateLimitEnabled`). It keeps sliding-window counters in Redis through the `windowcounter` package of `traefik-middleware-utilities`, vendored at the version `go.mod` already pins (`v1.0.7`, no module bump).
- New public settings: `rateLimitEnabled`, `rateLimitStore` (only `redis` in this version), `rateLimitRedisHost`, `rateLimitRedisPassword`, `rateLimitRedisPasswordFile`, `rateLimitRedisDatabase`, `rateLimitSyncRate` (default `200ms`; `0` = one Redis round trip per hit), `rateLimitFailureAction` (`passthrough` | `ban` | `captcha`, default `passthrough`), `rateLimitStatusCode` (default 429), `rateLimitResponseHeaders` (default true), and the list `rateLimitBuckets`.
- A bucket row carries a unique `name`, the same request predicates as a `bouncerActionRules` row (`method`, `path`, `host`, `headers`, `cookies`, flat on the row; none set = every request), a `key` list (`from: ip | header | cookie | query | host | path | method`, with `name`, `pattern` capture group, `ipv4Prefix`, `ipv6Prefix`), `algorithm` (only `slidingWindow` in this version), `requests`, `window` (whole seconds, at least 1s), `action` (`deny` | `log`), and `final`.
- Request path: the rate limit runs after the LAPI step and before the AppSec step (the action-rule captcha gate and AppSec come after it). Trusted clients, action-rule bans, and requests LAPI already answered are not charged.
- Matching buckets are charged in list order. The first `deny` bucket over its limit answers with `rateLimitStatusCode` through the ban page and a `Retry-After` header. A `log` bucket over its limit only logs. `final: true` stops after that bucket. A bucket whose key value is missing is skipped.
- When Redis cannot answer, `rateLimitFailureAction` applies. The whole rate-limit step has a fixed time budget per request, so a Redis outage adds a bounded delay.
- New `bouncerActionRules` token `bypassRateLimit` that skips only the rate limit. `bypass` keeps its meaning (LAPI and AppSec).
- Remediation header: `ban:ratelimit:<bucket>` on a deny, `ban:ratelimit-failure` / `captcha:ratelimit-failure` for the failure action. Usage-metrics drops use origin `plugin:ratelimit:<bucket>` and `plugin:ratelimit_failure`.
- `rateLimitStore: memory`, `algorithm: tokenBucket`, `burst`, bucket `action: captcha`, and `RateLimit-*` response headers are not in this version. The first four fail `ValidateParams` with a message that says so, instead of being dropped silently by Traefik's config decode. Each has a follow-up note in `knowledge/debt/`.
- **Not BREAKING.** A configuration without `rateLimitEnabled: true` behaves as before.

## Capabilities

### New Capabilities

- `core_plugin_ratelimit_client`: the rate-limit leg's Redis-backed counter: when it is opened and shared, the Redis key layout, sync rate, the per-request time budget, and what a Redis failure does.
- `core_plugin_ratelimit_buckets`: bucket rows: which requests a bucket counts, what the counter is per, evaluation order, `deny` / `log` / `final`, and the deny response.

### Modified Capabilities

- `core_plugin_middleware_bouncer`: new requirement "The rate limit runs between the LAPI step and the AppSec step"; "Action rules fold every matching row" adds the `bypassRateLimit` token and its skip flag; "Structured remediation header values" adds the `ratelimit` reasons and lets reason `ratelimit` carry the bucket name as the third field.
- `core_plugin_middleware_config-validation`: new requirement "Rate-limit settings are validated only when the leg is enabled".
- `core_plugin_lapi_usage-metrics`: new requirement "Rate-limit drops use plugin origins".
- `build_e2e_pester_crowdsec-stack`: new requirement "Real stack covers the Redis rate limit".

## Impact

- New package `pkg/ratelimit` (bucket authoring type, compile, evaluation, Redis-backed `Client`).
- `go.mod` unchanged; `vendor/` gains `traefik-middleware-utilities/windowcounter` (`vendor/modules.txt`).
- `plugin.go` (open the leg on the bind context and hand it to the Bouncer), `pkg/configuration/configuration.go` (new keys, defaults, validation), `pkg/httprule` (token, catch-all compile, exported host owner), `pkg/ip` (prefix mask), `pkg/bouncer` (new step, header reasons, drops), `pkg/lapi/client_metrics.go` (origins).
- Tests: unit tests per package, a `realredis` Go test against Dragonfly, a Yaegi program through `pkg/yaegitest`, and a real-stack Pester file `tests/e2e/real/rate_limit.Tests.ps1` with `tests/e2e/real/config/dynamic/rate-limit.yml`.
- Docs: `README.md` (rate-limit section, settings reference, header table, "What changed"), devdocs usage packet for the leg.
