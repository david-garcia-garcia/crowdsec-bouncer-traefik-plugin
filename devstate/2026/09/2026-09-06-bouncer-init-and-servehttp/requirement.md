# Requirement
IssueKey: 2026-09-06-bouncer-init-and-servehttp

## Problem
Three defects in `pkg/bouncer` constructor and request path: (1) `crowdsecMode: appsec` skips captcha client initialization, so `crowdsecAppsecFailureAction: captcha` bans instead of serving captcha when AppSec fails; (2) `New` discards `ip.NewChecker` and `configuration.GetTemplate` errors, allowing degraded IP trust or empty ban bodies without startup failure; (3) `ServeHTTP` / remediation orchestration branches lack direct unit tests, so regressions in stream-health, cache, redis-unreachable, and captcha paths would not fail CI at the bouncer layer.

## Current (code)
- `pkg/bouncer/bouncer.go:80-82` — `New` returns before `captchaClient.New` when `config.CrowdsecMode == configuration.AppsecMode`; captcha stays zero-value (`Valid == false`).
- `pkg/bouncer/bouncer.go:307-309` — AppSec `ErrFailureCaptcha` routes to `handleRemediationServeHTTP` with `cache.CaptchaValue`.
- `pkg/bouncer/bouncer.go:281-290` — captcha served only when `b.captchaClient.Valid`; otherwise `handleBanServeHTTP`.
- `pkg/configuration/configuration.go:519` — `validateFailureAction` allows `crowdsecAppsecFailureAction: captcha` when `CaptchaProvider` is set (validation passes; bouncer never initializes captcha in appsec mode).
- `pkg/bouncer/bouncer.go:49-50` — `serverChecker, _ := ip.NewChecker(...)` and `clientChecker, _ := ip.NewChecker(...)` discard errors.
- `pkg/bouncer/bouncer.go:55` — `banTemplate, banTemplateContentType, _ = configuration.GetTemplate(...)` discards error.
- `pkg/bouncer/bouncer.go:76-77` — nil checkers stored on `PoolStrategy` regardless of `NewChecker` outcome.
- `pkg/ip/checker.go:102-105` — `PoolStrategy.getIP` returns immediately when `Checker == nil`; forwarded headers not walked.
- `pkg/bouncer/bouncer.go:256-257` — `handleBanServeHTTP` writes status/header only when `banTemplate == nil`.
- `pkg/bouncer/bouncer.go:125-218` — `ServeHTTP` decision tree (enabled, IP errors, trusted bypass, appsec mode, cache hit/miss, redis unreachable, stream unhealthy, live lookup, failure actions).
- `pkg/bouncer/bouncer.go:221-231` — `applyLapiFailureAction` including `FailureActionCaptcha` branch.
- `pkg/bouncer/bouncer_test.go` — tests `handleBanServeHTTP`, `handleNextServeHTTP`, partial `applyLapiFailureAction`; no `ServeHTTP` or `handleRemediationServeHTTP` calls.
- `pkg/bouncer/bouncer_test.go:100-123` — `TestCaptchaMethodBasedLogic` asserts inline formula, not handler behavior.
- `plugin_test.go:271-318` — integration-level `TestBouncer_ServeHTTP_Matrix` (disabled, trusted IP, live ban/allow only).
- not found — bouncer-layer tests for stream-unhealthy cache miss, redis unreachable policy, cache fail-closed, captcha cache hit/miss via `ServeHTTP`, `applyLapiFailureAction` captcha, AppSec `ErrFailureCaptcha`.

## Desired
- Initialize `captchaClient` in appsec mode when captcha is required for failure-action handling (at minimum when `crowdsecAppsecFailureAction` is `captcha` and captcha provider is configured).
- Propagate or fail startup on non-nil `NewChecker` and `GetTemplate` errors from `New` (fail closed on checker errors; surface ban-template load failures).
- Add focused `pkg/bouncer` tests calling `ServeHTTP` and `handleRemediationServeHTTP` with stub clients for: cache hit ban/captcha; cache miss + stream unhealthy (each `lapiFailureAction`); redis unreachable block true/false; non-miss cache error fail-closed; IP parse/trust fail-close; captcha remediation with valid client (Check pass and ServeHTTP path); `applyLapiFailureAction` captcha; AppSec `ErrFailureCaptcha` through `handleNextServeHTTP`. Replace `TestCaptchaMethodBasedLogic` with a handler-invoking test.

## Affected
- `pkg/bouncer/bouncer.go` — `New`, possibly captcha init guard for appsec mode.
- `pkg/bouncer/bouncer_test.go` — new ServeHTTP/remediation coverage; replace formula-only captcha test.

## Out of scope
- Plugin constructor rollback (`plugin.go` / plugin ticket).
- Captcha handler internals (`pkg/captcha` wiring beyond bouncer init call).
- Configuration validation changes in `pkg/configuration` (reject appsec+captcha at validate time is an alternative, not in scope for this ticket).
- Structured AppSec JSON `action: captcha` envelopes (failure captcha via `ErrFailureCaptcha` only).
- LAPI/cache captcha paths in pure appsec mode where `ServeHTTP` skips LAPI entirely.
- `pkg/ip` GetRemoteIP unit tests (`pkg/ip/checker_test.go`).
- E2E docker tests under `tests/e2e/real`.

## Unknowns
- Whether captcha init in appsec mode should be conditional on `crowdsecAppsecFailureAction == captcha` only, or also when LAPI failure-action captcha could apply in mixed deployments (appsec mode skips LAPI in `ServeHTTP` — LAPI captcha init may be unnecessary).
- Whether `GetTemplate` failure in `New` should hard-fail constructor or log loudly and continue (ticket allows either; explore should pick one).

## Tensions
- Sibling finding suggests rejecting appsec+captcha at validate time as an alternative; scope bound is `pkg/bouncer` only — validation fix deferred.
- `ValidateParams` already calls `ip.NewChecker` and loads ban template; redundant calls in `New` may succeed in normal Traefik startup but fail if invoked without prior validation — ticket wants explicit error surfacing, not necessarily deduplication.
- Captcha `GetVariable` errors on lines 84-85 are also ignored; same pattern as checker/template but captcha init path validates provider separately — may be acceptable if out of captcha-package scope.
