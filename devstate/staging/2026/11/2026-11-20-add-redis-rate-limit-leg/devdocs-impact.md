# Devdocs impact
change: share-rate-limit-leg-and-bucket-actions

Pin: `origin/master` at head `c4f6d71b` (147 reviewable paths, 24 excluded; `git-sync` merged master's `d5b0be84`, README and `instance_severance` only). Round 2 units only; round 1's units are below as history. Domain read: `index_core_plugin.md`, `index_build_e2e.md`.

## Units
- Published leg table and leg binding — pattern — `plugin.go` (`publishedLegs`, `publishedLeg`), `pkg/bouncer/leg_binding.go` (`legBinding`, `receiveBinding`, `traceBinding`); spec `core_plugin_middleware_instance-slots`
- Shared rate-limit leg (owner / subscriber) — subsystem — `pkg/ratelimit/client.go` (`Settings`, `Policy`, `OwnershipKey`, `Incarnation`), `plugin.go` (`prepareRateLimit`, `rateLimitSettings`), `pkg/bouncer/bouncer_leg_ratelimit.go`; specs `core_plugin_ratelimit_client`, `core_plugin_middleware_instance-slots`
- Bucket actions and walk — subsystem — `pkg/ratelimit/charge.go`, `bucket_set.go` (`ratelimit | captcha | log`, `Verdict.RateLimit` / `Verdict.Captcha`, skipped bucket); spec `core_plugin_ratelimit_buckets`
- Rate-limit counter contract and algorithm — subsystem — `pkg/ratelimit/counter.go`, `sliding_window_counter.go`, `token_bucket_counter.go` (`rateLimitAlgorithm`, `burst`, `:tb`); specs `core_plugin_ratelimit_client`, `core_plugin_ratelimit_buckets`
- Rate-limit captcha answers and challenge-form answer — pattern — `pkg/bouncer/bouncer_serve_ratelimit.go` (`answerCaptchaBucket`, `isRateLimitChallengeFormAnswer`, `captchaRateLimitFailure`, `logRateLimitCaptchaDowngrade`); specs `core_plugin_middleware_bouncer`, `core_plugin_ratelimit_buckets`
- Owner-unavailable logging — pattern — `pkg/bouncer/rate_limit_owner_warnings.go`; spec `core_plugin_middleware_instance-slots`
- Middleware New and the Bouncer pipeline — subsystem — `plugin.go`, `pkg/bouncer/bouncer.go` (`Subscriptions`); spec `core_plugin_middleware_bouncer`
- Captcha request routing — subsystem — `handleCaptchaKindServeHTTP` gains the rate-limit step as a caller
- Action rules — pattern — `bypassCaptcha` on a rate-limit `captcha` bucket
- Config validation — subsystem — `pkg/configuration/configuration.go` (`RateLimitInstanceName`, `RateLimitAlgorithm`, owner-only `validateRateLimit`, rate-limit E2 row); spec `core_plugin_middleware_config-validation`
- LAPI usage-metrics — subsystem — `pkg/lapi/client_metrics.go` (`OriginPluginRateLimitChallengeForm`); spec `core_plugin_lapi_usage-metrics`
- Admission gate and Redis client on utilities `v1.0.10` — subsystem — `pkg/admission/admission.go` (`Admit` checks the context; `backendbackoff.Gate.Allow` takes none), `go.mod`
- Real-stack e2e — pattern — `tests/e2e/real/rate_limit_shared.Tests.ps1`, `rate_limit_captcha.Tests.ps1`, `rate_limit.Tests.ps1` (token bucket); spec `build_e2e_pester_crowdsec-stack`

Already current (no finding), checked against the tree: `core_plugin_ratelimit` (Language: Rate-limit Client, Algorithm, Owner / subscriber, Bucket, Walk, Skipped bucket, Counter key; usage, snippet, gotchas for owner warnings and the challenge-form answer), `core_plugin_middleware_config-validation` (`RateLimitEnabled` = own, `RateLimitInstanceName`, E2 row, `validateRateLimit` order with `rateLimitAlgorithm`), `core_plugin_middleware_ban-page`, `core_plugin_httprule`, `build_e2e_real` (shared-leg, captcha-bucket, token-bucket fixtures and the client-address rule). All were updated by implement.

Skipped: tests, Pester and compose fixtures, `.golangci.yml`, `vendor/` (external surface is `knowledge/research/ext_traefik-middleware-utilities_*`), README (not a packet), `openspec/` trees.

## Findings
- [x] stale-usage  Middleware New — `core_plugin_middleware`: Bouncer term says four `atomic.Value` bindings; Two configuration axes omits `rateLimitEnabled`; the `publishedLegs()` walk lists four legs, four `prepare`s, and four groups; Failure action term and the per-router gotcha do not say the rate-limit failure action is the owner's policy (subscribers cannot disagree); Action rule term omits skipRateLimit; `Receive*` and the Watch log list omit `ReceiveRateLimit` and `crowdsec ratelimit instance`
- [x] stale-usage  Instance slots — `core_plugin_middleware_instance-slots`: snippet calls `receiveBinding` with four arguments (now `onBind, onUnbind`); the add-a-leg bullet names only an `onBind` hook; `index_core_plugin.md` row lists four legs
- [x] stale-usage  Rate-limit leg — `index_core_plugin.md` row for `core_plugin_ratelimit` says the Client is opened per middleware (packet itself is current)
- [x] stale-usage  Captcha request routing — `core_plugin_middleware_captcha-routing`: callers of `handleCaptchaKindServeHTTP` and their reasons omit the rate-limit step, and the rule that it reaches the handler only with a usable captcha (no per-request unsubscribed WARN)
- [x] stale-usage  Action rules — `core_plugin_middleware_action-rules`: `bypassCaptcha` "return false, the caller continues" has an exception the packet omits (a `captcha` bucket answers as `ratelimit`); `isRateLimitChallengeFormAnswer` reads `BypassCaptchaName` directly; overview OR list omits skipRateLimit
- [x] stale-usage  LAPI usage-metrics — `core_plugin_lapi_usage-metrics`: "a challenge-form POST that continues" is not a drop-free path any more; since `e4e19906` a marker POST the gate does not answer is charged
- [x] stale-usage  Admission gate / Redis client — `core_plugin_appsec`, `core_plugin_modsecurity_client`, `core_plugin_decisionstore` name utilities `v1.0.7`; `go.mod` pins `v1.0.10`, and `backendbackoff.Gate.Allow` lost its context (`Admit` now checks it)

---

# Devdocs impact — round 1 (history)
change: add-redis-rate-limit-leg

Pin: `origin/master` at head `7dfa9648` (69 reviewable paths, 22 excluded). Domain read: `index_core_plugin.md`, `index_build_e2e.md` only.

### Units
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

### Findings
- [x] stale-usage  Rate-limit leg — `core_plugin_ratelimit` key-part owners omit `method`, the capture-group `pattern`, and the missing-value skip (its `final` included); the Verdict bullet omits `EffectiveRateLimitFailureAction`, the failure header/origin, and `captchaRateLimitFailure` asking `bypassesCaptcha`; no gotcha for the `debugCappedLogger` cap on `simpleredis` (codereview fix `f2badbea`)
- [x] stale-usage  Middleware New — `core_plugin_middleware` still says ServeHTTP order is LAPI, AppSec, ModSec and that it loads `atomic.Value` only; Bouncer-owned list omits the rate-limit settings; header rule says only `lapi` takes a third field; action-rule and trusted skip lists omit the rate limit; root row description omits the rate-limit Client (`index_core_plugin.md`)
- [x] stale-usage  Ban page — `core_plugin_middleware_ban-page` Language and How-to say only the AppSec ban calls `handleBanStatusServeHTTP`; the rate-limit deny now does with `rateLimitStatusCode`; third-field rule omits `ratelimit`; index row description updated with it
- [x] stale-usage  Action rules — `core_plugin_middleware_action-rules` lists the functions that ask `bypassesCaptcha` without `captchaRateLimitFailure`
- [x] stale-usage  HTTP request rules — `core_plugin_httprule` has no `NewWithCatchAll`, no exported `RequestHostname` as the one host owner, no `CompileRowName`; the fully-empty reject is stated as universal
- [x] stale-usage  `pkg/ip` — `core_plugin_ip` has no `MaskPrefix` (new helper the rate-limit `ip` key part calls on the `GetRemoteIP` address)
- [x] stale-usage  LAPI usage-metrics — `core_plugin_lapi_usage-metrics` Language term and How-to origin lists omit `plugin:ratelimit:<bucket>` and `plugin:ratelimit_failure`
- [x] stale-usage  Config validation — `core_plugin_middleware_config-validation` has no `validateRateLimit` gate (store, host, password file, sync rate, failure action, status, buckets) and omits `rateLimitFailureAction` from the captcha-instance-name rule
- [x] language-gap  Config validation — `core_plugin_middleware_config-validation` defines `AppsecEnabled`, `CaptchaEnabled`, `ModsecEnabled` but not `RateLimitEnabled`, the field `New`, `bouncer.New`, and `ValidateParams` all gate the leg on
