# Devdocs impact
change: add-redis-rate-limit-leg

Pin: `origin/master` at head `7dfa9648` (69 reviewable paths, 22 excluded). Domain read: `index_core_plugin.md`, `index_build_e2e.md` only.

## Units
- Rate-limit leg — subsystem — `pkg/ratelimit/`, `pkg/bouncer/bouncer_serve_ratelimit.go`; specs `core_plugin_ratelimit_client`, `core_plugin_ratelimit_buckets`
- Middleware New and the Bouncer pipeline — subsystem — `plugin.go` (`openRateLimit`), `pkg/bouncer/bouncer.go` (`serveRateLimit` step, `AttachRateLimit`); spec `core_plugin_middleware_bouncer`
- Remediation header — pattern — `pkg/bouncer/remediation_header.go` (`headerThirdField`, reason `ratelimit` / `ratelimit-failure`)
- Ban page — pattern — `handleBanStatusServeHTTP` with `rateLimitStatusCode`
- Action rules — pattern — `pkg/httprule/action.go` (`bypassRateLimit`, `SkipRateLimit`), `captchaRateLimitFailure` asking `bypassesCaptcha`
- HTTP request rules — subsystem — `pkg/httprule/set.go` (`NewWithCatchAll`, exported `RequestHostname`), `CompileRowName`
- Trusted-IP lookup / `pkg/ip` — subsystem — `pkg/ip/network.go` (`MaskPrefix`)
- LAPI usage-metrics — subsystem — `pkg/lapi/client_metrics.go` (`plugin:ratelimit:<bucket>`, `plugin:ratelimit_failure`); spec `core_plugin_lapi_usage-metrics`
- Config validation — subsystem — `pkg/configuration/configuration.go` (`validateRateLimit`, `RateLimitSyncRateDuration`, `EffectiveRateLimitFailureAction`, `RateLimitEnabled`); spec `core_plugin_middleware_config-validation`
- Go-layer real Redis e2e — pattern — `pkg/ratelimit/zzz_e2e_realredis_test.go`, `Makefile` `test_realredis`, `.github/workflows/e2e.yml`
- Real-stack e2e — pattern — `tests/e2e/real/rate_limit.Tests.ps1`, `config/dynamic/rate-limit.yml`

Already current (no finding): `build_e2e_go-redis` (Language, key files, per-run nonce gotcha) and `build_e2e_real` (key files, Dragonfly / file-provider / `dragonfly:1` gotcha), both updated by implement and checked against the tree.

Skipped: tests, compose fixtures, `.golangci.yml` depguard lists, `vendor/` (external surface lives in `knowledge/research/ext_traefik-middleware-utilities_windowcounter/`), README (not a devdocs packet).

## Findings
- [x] stale-usage  Rate-limit leg — `core_plugin_ratelimit` key-part owners omit `method`, the capture-group `pattern`, and the missing-value skip (its `final` included); the Verdict bullet omits `EffectiveRateLimitFailureAction`, the failure header/origin, and `captchaRateLimitFailure` asking `bypassesCaptcha`; no gotcha for the `debugCappedLogger` cap on `simpleredis` (codereview fix `f2badbea`)
- [x] stale-usage  Middleware New — `core_plugin_middleware` still says ServeHTTP order is LAPI, AppSec, ModSec and that it loads `atomic.Value` only; Bouncer-owned list omits the rate-limit settings; header rule says only `lapi` takes a third field; action-rule and trusted skip lists omit the rate limit; root row description omits the rate-limit Client (`index_core_plugin.md`)
- [x] stale-usage  Ban page — `core_plugin_middleware_ban-page` Language and How-to say only the AppSec ban calls `handleBanStatusServeHTTP`; the rate-limit deny now does with `rateLimitStatusCode`; third-field rule omits `ratelimit`; index row description updated with it
- [x] stale-usage  Action rules — `core_plugin_middleware_action-rules` lists the functions that ask `bypassesCaptcha` without `captchaRateLimitFailure`
- [x] stale-usage  HTTP request rules — `core_plugin_httprule` has no `NewWithCatchAll`, no exported `RequestHostname` as the one host owner, no `CompileRowName`; the fully-empty reject is stated as universal
- [x] stale-usage  `pkg/ip` — `core_plugin_ip` has no `MaskPrefix` (new helper the rate-limit `ip` key part calls on the `GetRemoteIP` address)
- [x] stale-usage  LAPI usage-metrics — `core_plugin_lapi_usage-metrics` Language term and How-to origin lists omit `plugin:ratelimit:<bucket>` and `plugin:ratelimit_failure`
- [x] stale-usage  Config validation — `core_plugin_middleware_config-validation` has no `validateRateLimit` gate (store, host, password file, sync rate, failure action, status, buckets) and omits `rateLimitFailureAction` from the captcha-instance-name rule
- [x] language-gap  Config validation — `core_plugin_middleware_config-validation` defines `AppsecEnabled`, `CaptchaEnabled`, `ModsecEnabled` but not `RateLimitEnabled`, the field `New`, `bouncer.New`, and `ValidateParams` all gate the leg on
