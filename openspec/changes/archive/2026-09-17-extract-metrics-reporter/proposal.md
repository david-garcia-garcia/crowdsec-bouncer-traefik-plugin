## Why

Usage-metrics counters and the POST path still live on `lapi.Client`, so the window rides the LAPI client’s identity. After #62 made HTTP+auth a replaceable `atomic.Value` transport, the parked extract can own that window without putting a write-once `*http.Client` on the reporter.

## What Changes

- Extract `MetricsReporter` in `pkg/lapi/client_metrics.go`. It owns the counter window, processed atomics, active-decision gauge maps, window/report mutexes, `lastMetricsPush`, and the POST/restore path.
- `Client` holds one `*MetricsReporter` for the existing reclaim lifetime. Tickers stay on `Client` (`metricsStop`, write-once `metricsInterval`, the same `startTicker` helper). No second ticker. No second reclaim table entry.
- The reporter POSTs through an injected query func bound to `crowdsecQuery` (loads `currentTransport()` each call). Snapshot write-once URL and envelope scalars at construct. Do not store `*http.Client`. Do not use `atomic.Pointer[T]`.
- `IncProcessed`, `IncDropped`, `rememberActiveDecision`, `forgetActiveDecision`, `reportMetrics`, `drainMetrics`, and `handleMetricsTicker` stay `Client` methods as thin forwards.
- When implement lands, delete `knowledge/debt/2026-09-17-metrics-reporter-split.md` and close that follow-up row.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_lapi_usage-metrics`: `MetricsReporter` owns the window; POST uses the replaceable transport; the reporter shares the Client reclaim lifetime (thin `Client` wrappers, one ticker, one table entry).

## Impact

- `pkg/lapi/client_metrics.go`, metrics fields and construction in `pkg/lapi/client.go`, `pkg/lapi/zzz_metrics_test.go`.
- Catalog leaf `openspec/specs/core_plugin_lapi_usage-metrics`.
- Debt file `knowledge/debt/2026-09-17-metrics-reporter-split.md` (delete on implement).
- Usage `knowledge/devdocs/core_plugin_lapi_usage-metrics.md` ticker sentence after apply (devdocsimpact). Call sites stay `Client.IncProcessed` / `IncDropped`.
- No **BREAKING** public JSON/YAML keys.
- Out of scope: `session.go` / `identity.go` reclaim keying, `client_http.go` reshape, `pkg/appsec/`, `pkg/captcha/`, cache/reclaim internals, instance-reclaim spec.
