# Requirement
IssueKey: 2026-09-17-lapi-metrics-reporter-split

## Problem
Usage-metrics counters and the POST ticker live on `lapi.Client`, so the window rides the LAPI client’s identity. After PR #62 made HTTP+auth a replaceable `atomic.Value` transport, a reporter split must own that window without putting a write-once `*http.Client` back on the reporter.

## Current (code)
- `handleMetricsTicker`, `drainMetrics`, `IncProcessed`, `IncDropped`, `addWindow`, `rememberActiveDecision`, `forgetActiveDecision`, `reportMetrics`, and `restoreMetricsWindow` are `Client` methods. Path: `pkg/lapi/client_metrics.go`.
- `Client` still holds the window and ticker: `metricsInterval`, `metricsStop`, `lastMetricsPush`, `startedAt`, `metricsMu`, `reportMu`, `windowCounters`, `processedIPv4` / `processedIPv6` / `processedUnknown`, `activeDecisions`, `activeDecisionSlots`. Path: `pkg/lapi/client.go`.
- `New` starts the metrics ticker with the same `startTicker` helper as the stream poller; `Close` / `Sleep` stop it and call `drainMetrics`; `Wake` starts it again. Path: `pkg/lapi/client.go`.
- `reportMetrics` POSTs through `c.crowdsecQuery`, which loads `currentTransport()` from `Client.transport` (`atomic.Value`, not `atomic.Pointer[T]`). Path: `pkg/lapi/client_http.go`.
- Tests construct a `Client` and attach HTTP via `attachTestTransport` (`pkg/lapi/zzz_session_test.go`), then call `Inc*` / `reportMetrics` / `Sleep` / `Close`. Path: `pkg/lapi/zzz_metrics_test.go`.
- No `MetricsReporter` type exists. Path: not found.
- Parked follow-up: `knowledge/debt/2026-09-17-metrics-reporter-split.md` (IssueKey there is the previous ticket).
- Usage-metrics contract: `openspec/specs/core_plugin_lapi_usage-metrics/spec.md`.
- Transport extract and Yaegi / write-once constraints: `openspec/changes/archive/2026-09-17-lapi-transport-router-policy/design.md`.

## Desired
Extract a `MetricsReporter` that owns the counter window and the reporting ticker so metrics stop riding the LAPI client’s identity. The reporter MUST POST through the replaceable transport (`atomic.Value` + `AdoptTransport`) and MUST NOT add its own write-once `*http.Client`. Same reclaim lifetime as the cursor: no second ticker and no second reclaim entry. Yaegi: `atomic.Value` with a why-comment, not `atomic.Pointer[T]`. Do not convert existing write-once `Client` scalars into mutable fields. When implement lands, delete `knowledge/debt/2026-09-17-metrics-reporter-split.md` and close that row on this run’s `issues.md` and delivery card.

## Affected
- `pkg/lapi/client_metrics.go`
- `pkg/lapi/client.go` (metrics fields and their construction only)
- `pkg/lapi/zzz_metrics_test.go`
- `openspec/specs/core_plugin_lapi_usage-metrics`
- `knowledge/debt/2026-09-17-metrics-reporter-split.md` (delete on implement)

## Out of scope
- Reclaim keying in `pkg/lapi/session.go` (`SessionKey`, `settingsFrom`, `streamSettings`, `CachePrefix`, `reclaimSessionKey`) and `pkg/lapi/identity.go`
- `openspec/specs/core_plugin_middleware_instance-reclaim/`
- `pkg/appsec/`, `pkg/captcha/`, and `core_plugin_appsec_*` leaves
- `pkg/cache/` internals and `pkg/reclaim/` internals
- Reshaping the HTTP transport or session code
- A second metrics ticker or a second reclaim table entry
- Making remaining write-once `Client` scalars mutable
- `atomic.Pointer[T]`

## Unknowns
- How the reporter reaches `crowdsecQuery` / `currentTransport()` without editing `pkg/lapi/client_http.go` (fenced: do not reshape transport) and without storing its own `*http.Client`.
- Whether `IncProcessed` / `IncDropped` stay as `Client` wrappers (bouncer call sites are outside this ticket’s file fence) or move onto the reporter with thin forwards only.

## Tensions
- The debt wants metrics off the client’s identity, but this ticket also forbids a second reclaim entry — `Client` must still hold the reporter for the cursor’s lifetime.
- `reportMetrics` today calls `crowdsecQuery` in `pkg/lapi/client_http.go`; the fence forbids reshaping that file, and #62 forbids a write-once HTTP field on the reporter.
- `attachTestTransport` lives in `pkg/lapi/zzz_session_test.go` (outside the test fence). Changing that helper would be blocked; new metrics tests must keep using it or stay inside `zzz_metrics_test.go`.
- Previous apply (`2026-09-17-lapi-transport-router-policy`) listed moving `MetricsReporter` as a non-goal; this ticket is that parked note, not a new product ask.
