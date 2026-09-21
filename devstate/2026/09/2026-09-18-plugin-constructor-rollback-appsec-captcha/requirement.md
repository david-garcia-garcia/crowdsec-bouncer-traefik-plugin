# Requirement
IssueKey: 2026-09-18-plugin-constructor-rollback-appsec-captcha

## Problem
Five defects, all reproduced on master `87d1084`, rebuilt from open PRs #31 and #33 (to be closed in this
ticket's favour by the owner) plus three lines salvaged from the closed #22. `New` never releases reclaim
holders it already opened when a later constructor step fails, so a failed constructor leaks a LAPI stream
ticker for the process lifetime. `lapiMode: appsec` with `appsecEnabled: false` starts a
middleware that enforces nothing and says nothing. The README never states that `lapiMode` and
`appsecEnabled` are independent axes. In appsec mode the captcha client is never initialised, so
`bouncerAppsecFailureAction: captcha` bans instead of challenging — a violation of
`core_plugin_appsec_failure-action`. And `New` mutates Traefik's own `*Config`, writing the resolved LAPI
secret back into the caller's struct.

## Current (code)
- `pkg/reclaim` is a shim over the shared utilities table; that table releases a holder only when the bound
  context is Done (`vendor/github.com/david-garcia-garcia/traefik-middleware-utilities/reclaim/table.go:490-524`,
  `context.AfterFunc`). `New` binds Traefik's own long-lived ctx into `lapi.OpenStream` / `lapi.OpenLive`
  (which also opens the decision store) and `appsec.Open`. `plugin.go:53-76`
- `New` returns `nil, err` on every failure path with no release of holders opened earlier. `plugin.go:37-77`
- `ValidateParams` accepts `lapiMode: appsec` without requiring `appsecEnabled`.
  `pkg/configuration/configuration.go:623`
- `plugin.go:59` skips both `OpenStream` and `OpenLive` for appsec mode, `plugin.go:70` opens no AppSec
  client when `AppsecEnabled` is false, and `Bouncer.ServeHTTP:182` routes straight to
  `handleNextServeHTTP`, which with `appsecEnabled` false just calls `next`.
- `README.md:64-72` lists the five modes; the `appsec` row is accurate but nothing says the WAF leg runs on
  the pass path in *every* mode (`pkg/bouncer/bouncer.go:341`), nor that `appsec` + disabled enforces nothing.
- `bouncer.New` returns early for appsec mode at `pkg/bouncer/bouncer.go:94`, before the captcha client is
  initialised, so `captchaClient.Valid` stays false. `applyAppsecServeHTTP:353` raises `ErrFailureCaptcha`,
  `handleRemediationServeHTTP:315` sees `!b.captchaClient.Valid` and bans.
- `New` writes through Traefik's pointer at `plugin.go:25`, `:29`, `:32`, then hands that pointer to
  `lapi.Prepare` (`pkg/lapi/client.go:80-96`: resolved `LapiKey`, `LapiRedisPassword`, and in alone
  mode `LapiHost` plus `LapiUpdateIntervalSeconds = 7200`) and `appsec.Prepare`
  (`pkg/appsec/client.go:27-43`: `AppsecKey`).
- `Config` carries `[]string` and `map[string]string` fields (`BouncerForwardedTrustedIPs`,
  `BouncerClientTrustedIPs`, `LapiRedisReadHosts`, `LapiCapiScenarios`, `LapiScopeHeaders`) that a shallow
  copy still shares with the caller.
- `configuration.New()` defaults `AppsecHost` to `crowdsec:7422` and
  `BouncerAppsecFailureAction` to `ban`. `pkg/configuration/configuration.go:172-174`

## Desired
1. Derive a bind context inside `New` and release every holder opened so far on any error path. Keep the
   named-`err` `defer`; do not revert to a closure-captured bool. Do not cancel on the success path.
   `bindCtx` stays a child of the constructor ctx so cancelling Traefik's context still releases the holder.
2. `lapiMode: appsec` with `appsecEnabled: false` logs a loud warning and still starts. Owner
   decision: warn, do not reject. Do not imply AppSec on.
3. README states the two axes explicitly, says that `appsec` + `appsecEnabled: false` enforces
   nothing, and mentions the warning. Existing style; do not restructure the mode table.
4. Initialise the captcha client when appsec mode needs it and condition the early return accordingly, so
   `bouncerAppsecFailureAction: captcha` serves the challenge in appsec mode.
5. `prepared := *config` plus passing `&prepared`, with a comment at the copy site naming the slice and map
   fields the snapshot does not protect.

## Affected
- `plugin.go`
- `pkg/bouncer/bouncer.go`
- `pkg/configuration/configuration.go`
- `README.md`
- `openspec/specs/core_plugin_middleware_bouncer/spec.md` (the sentence naming the constructor ctx as the
  AppSec reclaim holder must name the derived bind context)
- `openspec/specs/core_plugin_middleware_config-validation/spec.md` (the new warning)
- `openspec/specs/core_plugin_appsec_failure-action/spec.md` (captcha in appsec mode)
- root tests (`zzz_*_test.go`), `pkg/configuration`, `pkg/bouncer`

## Out of scope
- #33's error plumbing for `ip.NewChecker` (`bouncer.go:52-53`) and `GetTemplate` (`:65`): unreachable,
  `ValidateParams` rejects the same inputs first and `ip.Checker.ContainsIP` has a nil guard that fails closed.
- #33's 419-line `servehttp_test.go`: its `testValidCaptchaClient(t, cacheClient)` helper cannot compile
  against master's stateless captcha client.
- Rejecting the appsec+disabled config, or implying `appsecEnabled` on.
- `pkg/decisionscope` keying and the `ApplyRangeBatch` read-side guard (#34, next ticket).
- Merging, closing, or commenting on #22, #31, #33.

## Unknowns
- Whether Yaegi v0.16.1 keeps a named return visible to a `defer` closure in `New` (#31's `37e1914` broke the
  docker e2e on exactly that construct and `2535b19` fixed it). `yaegi test -v .` is the local gate.
- Whether the real-stack Pester e2e is green on the pushed head: it cannot run locally (hard-coded ports
  8000/8080/8081 and subnet `172.20.0.0/16` collide with the owner's long-running dev stack).

## Tensions
- `core_plugin_middleware_bouncer` says `New` "uses the constructor ctx as the AppSec reclaim holder". A
  derived bind context keeps that intent but not that wording, so the leaf has to be updated or a strict
  reader sees a violation. `std_go_reclaim_context-lease` only requires that `Open` bind *a* context.
- Deliverable 5 is behaviour-neutral by construction. The ticket says it must not grow: if it starts
  requiring test changes beyond the constructor, drop it and say so.
