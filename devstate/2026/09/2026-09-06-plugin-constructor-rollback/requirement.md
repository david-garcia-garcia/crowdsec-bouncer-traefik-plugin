# Requirement
IssueKey: 2026-09-06-plugin-constructor-rollback

## Problem
`plugin.go` `New` can bind reclaimed LAPI and AppSec clients, then return an error from a later step without releasing earlier opens — stream/metrics tickers keep running. `crowdsecMode: appsec` with `crowdsecAppsecEnabled: false` succeeds and forwards all non-trusted traffic with no CrowdSec enforcement. Constructor mode branches and error paths lack direct tests.

## Current (code)
- `plugin.go:53-77` — opens LAPI (`OpenStream` for stream/alone, skips LAPI for `AppsecMode`, else `OpenLive`), optionally `appsec.Open`, then `bouncer.New`; any error after an open returns `nil, err` with no rollback of prior reclaim holders.
- `pkg/reclaim/table.go:244-245` — successful `OpenWithGrace` starts `watch` on constructor `ctx`; tickers stop only when the last holder drops after grace.
- `pkg/lapi/client_stream.go:37-44` — stream mode starts immediate poll and ticker inside `lapi.New` from the reclaim `create` callback.
- `plugin.go:59-67` — `AppsecMode` skips `lapi.OpenStream` / `lapi.OpenLive`; `lapiClient` stays nil.
- `plugin.go:70-76` — `appsec.Open` runs only when `config.CrowdsecAppsecEnabled` is true.
- `pkg/configuration/configuration.go:361` — `ValidateParams` waives LAPI key for `AppsecMode` but does not require `CrowdsecAppsecEnabled`.
- `pkg/bouncer/bouncer.go:156-158` — `AppsecMode` bypasses LAPI lookup and calls `handleNextServeHTTP`.
- `pkg/bouncer/bouncer.go:294-298` — AppSec runs only when `appsecEnabled`; with it false, traffic goes to `next`.
- `plugin_test.go:66-86` — helpers `cfgLiveAt` / `cfgStreamAt` only; no appsec/alone variants.
- `plugin_test.go:111-421` — reclaim tests use live or stream only; no test where `appsec.Open` or `bouncer.New` fails after LAPI open and asserts reclaim release.
- not found — `TestNew_*` covering `AloneMode`, `AppsecMode`, `CrowdsecAppsecEnabled: true` with live/stream, or constructor error rollback.

## Desired
- On any error after `lapi.Open*` / `appsec.Open` in `New`, drop reclaim holders opened in that call before returning (defensive; do not rely on Traefik cancel timing).
- When `crowdsecMode` is `appsec`, fail `New` if AppSec is not enabled/configured — no pass-through bouncer (check in `plugin.go` after `ValidateParams` is acceptable within scope).
- Add focused `plugin_test.go` coverage: alone mode stream session; appsec-only with enabled; live/stream + AppSec enabled (distinct reclaim keys); constructor error after LAPI open leaves no stray reclaim holders.

## Affected
- `plugin.go` (constructor rollback + appsec-mode guard)
- `plugin_test.go` (mode branches and error rollback tests)

## Out of scope
- `pkg/captcha`, bouncer `ServeHTTP` paths and tests
- Reclaim concurrent first-Open races (`pkg/reclaim`)
- Traefik exact cancel timing on failed constructors
- Full `ValidateParams` matrix changes in `pkg/configuration/configuration.go` (unless a one-line guard is required and cannot live in `plugin.go`)
- AppSec runtime query/failure-action behavior (`pkg/bouncer`, `pkg/appsec`)
- LAPI key validation rules for non-appsec modes
- E2e Traefik reload timing; `version.go`

## Unknowns
- Whether appsec-mode rejection belongs solely in `plugin.go` or also needs `ValidateParams` in `configuration.go` (scope prefers `plugin.go`).
- Whether `bouncer.New` failure after both backends open requires rolling back both LAPI and AppSec holders (likely yes; confirm in explore/implement).

## Tensions
- Appsec pass-through fix: finding cites `ValidateParams` gap at `configuration.go:361`; ticket scope is `plugin.go` / constructor tests only — guard in `New` may diverge from centralized validation until a configuration ticket lands.
- Rollback mechanism: explicit `Drop` per opened holder vs scoped sub-context cancel — reclaim API choice affects `plugin.go` shape only within scope.
