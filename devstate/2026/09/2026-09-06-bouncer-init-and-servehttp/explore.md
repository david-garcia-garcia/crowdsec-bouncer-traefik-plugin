# Explore
IssueKey: 2026-09-06-bouncer-init-and-servehttp

## Concepts
- `Bouncer.New` builds per-router handlers; appsec mode currently returns before `captchaClient.New`, leaving `Valid == false`.
- `handleRemediationServeHTTP` gates captcha on `b.captchaClient.Valid`; invalid client always bans.
- `ServeHTTP` is a mode dispatcher: appsec skips LAPI entirely; stream/live/alone consult cache then stream health or live lookup.
- `ValidateParams` already validates checkers and ban template, but `New` re-calls and discards errors — defense-in-depth gap for direct `New` callers.
- Existing test pattern: construct `Bouncer` with partial fields + `lapi.NewTestLapiFailureActionClient` for failure-action tests; no exported helper yet for stream health / cache / redis flags.

## Decisions
- Init captcha in appsec mode when `EffectiveFailureAction(CrowdsecAppsecFailureAction) == captcha` and `CaptchaProvider != ""`; skip captcha init otherwise (LAPI failure-action captcha is unreachable in appsec mode because `ServeHTTP` never enters LAPI branches).
- Propagate `ip.NewChecker` and `configuration.GetTemplate` errors from `New` — fail constructor (fail closed), matching existing captcha init error handling.
- Add `pkg/lapi/test_servehttp.go` exported stub constructor for bouncer-layer `ServeHTTP` tests (stream health, redis block, cache client, mode, live lookup stub). Keeps test wiring out of product `bouncer.go`.
- Replace `TestCaptchaMethodBasedLogic` with tests calling `handleRemediationServeHTTP` using a captcha client with `Valid: true` and stub `Check`/`ServeHTTP` behavior via field assignment (no pkg/captcha internals).
- AppSec `ErrFailureCaptcha` bouncer test: appsec 500 + `appsecFailureAction: captcha` + `captchaClient.Valid: true` must not ban.

## Open questions
- Q: Should captcha init in appsec mode be conditional on `crowdsecAppsecFailureAction == captcha` only, or also when LAPI failure-action captcha could apply?
  Decision: assumed — appsec mode only needs captcha when AppSec failure-action is captcha; LAPI branches are skipped in `ServeHTTP`.
  By: explore

- Q: Should `GetTemplate` failure in `New` hard-fail or log loudly?
  Decision: assumed — return error from `New` (fail closed, consistent with captcha init).
  By: explore

- Q: Who owns client IP for ServeHTTP fail-close tests?
  Decision: assumed — reuse `ip.GetRemoteIP` + `PoolStrategy`; test nil `ipAddr` and checker errors via constructed requests and pool strategies (no duplicate IP logic in bouncer tests).
  By: explore
