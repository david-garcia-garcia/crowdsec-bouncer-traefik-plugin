# Requirement
IssueKey: 2026-09-05-split-connection-files

## Problem
`pkg/crowdsecconnection/connection.go` is one file with seven jobs (construct/close, stream ticker, live lookup, AppSec HTTP, LAPI/CAPI HTTP, metrics, shared types). The package already split reclaim identity and decision cache helpers; the remaining god file still packs the rest.

## Current (code)
- Same package `crowdsecconnection`. Path: `pkg/crowdsecconnection/`.
- `connection.go` is 842 lines: `CrowdsecConnection`, `Prepare`, `New`, `Close`, range membership, stream ticker (`startStream`, `handleStreamTicker`, `handleStreamCache`), live (`LiveLookup`, `handleNoStreamCache`), AppSec (`AppsecQuery` and helpers), CAPI login (`getToken`), LAPI HTTP (`crowdsecQuery`), metrics (`reportMetrics`), plus shared types `Decision`/`Stream`/`Login`/`AppsecResponse`. Path: `pkg/crowdsecconnection/connection.go`.
- Reclaim identity already lives in `identity.go` (`IdentityHex`, `Key`). Path: `pkg/crowdsecconnection/identity.go`.
- Stream store/delete, stream query string, and live LAPI decision parse already live in `connection_decisions.go`. Path: `pkg/crowdsecconnection/connection_decisions.go`.
- Tests in the same package: `appsec_test.go`, `connection_range_test.go`, `failure_action_test.go`, `test_appsec_connection.go`. Path: `pkg/crowdsecconnection/`.
- Exported API from `connection.go`: `CrowdsecConnection`, `Prepare`, `New`, `Close`, `Cache`, `RangeMembership`, `Mode`, `StreamHealthy`, `LapiFailureAction`, `RedisUnreachableBlock`, `StreamFetches`, `IncBlocked`, `LiveLookup`, `AppsecQuery`, `AppsecPolicy`, `AppsecResponse`, `AppsecAction*`, `ErrFailureCaptcha`, `Decision`, `Stream`, `Login`. Path: `pkg/crowdsecconnection/connection.go`.

## Desired
Move the remaining jobs into same-package files matching the existing `identity.go` / `connection_decisions.go` pattern:

- `connection_appsec.go`
- `connection_stream.go`
- `connection_live.go`
- `connection_http.go`
- `connection_metrics.go`

`CrowdsecConnection` type and exported API stay the same. No new packages. No behavior change. Tests still pass.

## Affected
- `pkg/crowdsecconnection/connection.go` (shrink; keep type, `Prepare`, `New`, `Close`, accessors)
- new files listed above under `pkg/crowdsecconnection/`
- usage packets that cite only `connection.go` as the AppSec/stream path (`knowledge/devdocs/core_plugin_appsec.md`, `knowledge/devdocs/core_plugin_decisionscope.md`) — path notes only, not a product change

## Out of scope
- `pkg/appsec` or any new package
- `GetTLSConfigCrowdsec` (sibling ticket)
- `identity.go`, `DecisionScopeHeaders`, cache constants, `pkg/ip`, `configuration.go` layout, `Prepare`/`plugin.go` mutation
- sibling tickets: 2026-09-05-split-configuration-files, 2026-09-05-split-ip-trust, 2026-09-05-scope-headers-identity, 2026-09-05-remediation-codes-owner, 2026-09-05-decisionscope-mode-bool, 2026-09-05-config-prepare-snapshot
- behavior, signatures, JSON tags, log strings, HTTP routes

## Unknowns
- Exact leftover in `connection.go` vs each new file (shared helpers: `startTicker` used by stream and metrics; `closeIdle` used by `Close`; AppSec types vs HTTP types).
- Whether DTO types (`Decision`, `Stream`, `Login`, `AppsecResponse`) stay in `connection.go` or move with their job.

## Tensions
- Caller said `connection.go` still owns stream, live lookup, AppSec, metrics, CAPI login, and LAPI HTTP, and also named five new files for those jobs. Read as: the **type** still owns those jobs (same package, methods on `CrowdsecConnection`); the **files** split like `identity.go`. Not a new package per job.
