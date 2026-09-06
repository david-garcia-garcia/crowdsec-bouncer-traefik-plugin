# Requirement
IssueKey: 2026-09-05-improve-metrics

## Problem
CrowdSec Console / LAPI usage metrics from this bouncer are a single unlabeled `dropped` count. Operators cannot slice remediations by scenario or by the other dimensions LAPI is able to ingest.

## Current (code)
- `CrowdsecConnection.reportMetrics` POSTs `v1/usage-metrics` with one `dropped` item (`unit: request`) whose only label is `type: traefik_plugin`. Window meta is `window_size_seconds` and `utc_now_timestamp`. Component identity is `type: bouncer`, `name: traefik_plugin`. Path: `pkg/crowdsecconnection/connection.go` (`crowdsecLapiMetricsRoute`, `reportMetrics`).
- `IncBlocked` adds one to a process-wide `blockedRequests` counter and takes no decision fields. Path: `pkg/crowdsecconnection/connection.go` `IncBlocked`.
- Ban, captcha challenge, and AppSec structured remediations all call `IncBlocked` with no scenario/origin/type/scope. Paths: `pkg/bouncer/bouncer.go` `handleBanServeHTTP`, `handleRemediationServeHTTP`, `handleAppsecResponseServeHTTP`.
- Stream/live cache stores only a remediation letter (`t`/`c`/`f`/`d`). `Decision.Scenario` (and `Origin`, `Type`, `Scope`) is parsed from LAPI then discarded at `storeStreamDecision`. Paths: `pkg/crowdsecconnection/connection.go` `Decision`; `pkg/crowdsecconnection/connection_decisions.go` `storeStreamDecision`; `pkg/cache/cache.go` `BannedValue` / `CaptchaValue`.
- E2E mock LAPI accepts `/v1/usage-metrics` and ignores the body. Path: `tests/e2e/mock/mocklapi/main.go`.
- No test asserts the usage-metrics JSON. Path: not found.

## Desired
- Usage-metrics items LAPI can ingest are sliced by **scenario**, plus every other label or metric name that CrowdSec LAPI actually accepts for a remediation component (not a guessed Prometheus surface).
- Console/cscli views that already consume those labels show this plugin’s remediations the same way official bouncers do.

## Affected
- `pkg/crowdsecconnection` metrics ticker and `IncBlocked`
- `pkg/bouncer` remediation paths that increment the counter
- Possibly cache/stream storage if scenario (or other labels) must survive until the request is dropped
- `tests/e2e/mock/mocklapi` if the push payload is asserted

## Out of scope
- Traefik/Prometheus scrape metrics (not LAPI `v1/usage-metrics`)
- Changing how decisions are matched (IP/Range/header scopes)
- New Traefik plugin config keys unless LAPI ingest requires an operator-facing toggle (ticket did not ask for one)
- Inventing label keys LAPI does not store
- Rewriting AppSec bot-detection beyond counting those remediations in the same LAPI payload

## Unknowns
- Exact metric names, units, and item `labels` keys LAPI accepts and Console displays (research folder `ext_crowdsec_lapi_usage-metrics` in flight).
- Whether AppSec / stream-unhealthy / LAPI-failure remediations have a scenario LAPI expects, or a different label (origin/type/name).
- Whether `labels.type: traefik_plugin` is a required component identity or a mistaken use of the remediation-type slot.

## Tensions
- Ticket asks for scenario slices; request-time lookup only has a cache letter, not `Decision.Scenario`.
- One counter mixes LAPI bans, captcha, AppSec, and failure remediations (`ReasonTECH` / `ReasonAPPSEC` / `ReasonLAPI`).
