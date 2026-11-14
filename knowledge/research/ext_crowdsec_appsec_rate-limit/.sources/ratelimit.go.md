---
url: https://github.com/crowdsecurity/crowdsec/blob/3d369d64eb3e9ba770ed39aedc83ffd3170aef4c/pkg/appsec/ratelimit.go
title: pkg/appsec/ratelimit.go RateLimit() helper
fetched: 2026-11-14
authority: source
ref: github.com/crowdsecurity/crowdsec@3d369d64eb3e9ba770ed39aedc83ffd3170aef4c:pkg/appsec/ratelimit.go
---

Pin = tag `v1.8.2`. File added by commit `ab20e2c2264fec1a711a7eedd203cea55484d54f` "waf: add RateLimit() helper (#4721)", 2026-10-20.

Constants: `rateLimitHelper = "RateLimit"`, `rateLimitScenario = "rate limit exceeded"`, fields `rate_limit_key` / `rate_limit`, `rateLimitIPv6PrefixLen = 64`.

`parseRateLimitSpec(key, limit)`: key must not be empty; limit is `<count>/<s|m|h>`, count a positive int; unit `s` = 1s, `m` = 1m, `h` = 1h; anything else is an error.

Identity (`rateLimitIdentityFor(clientIP, sourceValue)`): non-empty source value -> `"value:"+value`; else client IP: IPv4-mapped is unmapped, IPv6 keyed on its /64 prefix, IPv4 on the full address -> `"ip:"+addr`. Namespaced so a value can never drain an IP budget.

Bucket: one `rateLimiter` per key; map identity -> `golang.org/x/time/rate` Limiter with rate `count/period` and burst `count`. `take()` = `AllowN(now, 1)`. Denied requests still update `lastSeen`. `sweep` drops entries idle >= one period. `RateLimits` "is shared by every runner of an appsec engine".

`RateLimit(state, request, key, sourceValue)`:

- unknown key -> error ("wiring bug").
- `!request.IsInBand` -> warn once per key "called out-of-band, ignoring: rate limiting only applies in-band, guard the hook with IsInBand"; return false; no token spent.
- token available -> return false.
- else `setOutcome(&HookOutcome{Action: BanRemediation, Reason: "rate limit exceeded"})`; if the request already had an outcome, return true without touching the response.
- Quote:

```go
state.Response.InBandInterrupt = true
state.Response.Action = BanRemediation
state.Response.BouncerHTTPResponseCode = w.Config.BouncerBlockedHTTPCode
state.Response.UserHTTPResponseCode = http.StatusTooManyRequests
```

- increments `cs_appsec_rate_limited_total{source,appsec_engine,key}`.
- builds a LOG event (`rateLimitEventFromRequest`) on every denial; builds an alert only when `claimAlert(id)` is true (first denial since that source entry was created) -> `NewAppsecOverflow(w.buildRateLimitAlert(...))` -> `EmitAlertAndEvent(overflow, &evt)`.

`buildRateLimitAlert`: `models.Alert` with `Scenario` "rate limit exceeded", `Message` "WAF rate limit: <ip> exceeded <expr> on <key>", `Source` scope Ip / value client IP, `Capacity` = count, `Leakspeed` = period/count, `Simulated` false, `Kind` "waf". No `Decisions`. `Remediation` is not set (Go zero value `false`).

Expr registration: `expr.Function("RateLimit", exprRateLimit, new(func(context.Context, string, string) bool), new(func(context.Context, string, string, string) bool))`. Comment: "rateLimitExprOptions is only given to pre_eval: RateLimit anywhere else fails to compile."
