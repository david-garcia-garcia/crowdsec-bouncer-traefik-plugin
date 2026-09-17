## 1. Extract MetricsReporter

- [ ] 1.1 Add `MetricsReporter` in `pkg/lapi/client_metrics.go` with the window maps, processed atomics, `activeDecisions` / `activeDecisionSlots`, `metricsMu`, `reportMu`, `lastMetricsPush`, snapshotted URL/envelope scalars (`scheme` / `host` / `path` / `pluginVersion` / `startedAt` / `crowdsecMode`), and an unexported query func
- [ ] 1.2 Move `addWindow`, `reportMetrics` body, `restoreMetricsWindow`, and gauge remember/forget bodies onto the reporter; keep `MetricsOrigin` and item helpers as package funcs
- [ ] 1.3 Do not store `*http.Client` on the reporter; do not add `atomic.Pointer[T]`

## 2. Wire Client

- [ ] 2.1 Add a `*MetricsReporter` field on `Client`; drop the moved window fields and `startedAt` from `Client`
- [ ] 2.2 In `New`, construct the reporter, bind the query func to `crowdsecQuery`, snapshot URL/envelope scalars, and keep `metricsInterval` / `metricsStop` / `startTicker` on `Client`
- [ ] 2.3 Keep `IncProcessed`, `IncDropped`, `rememberActiveDecision`, `forgetActiveDecision`, `reportMetrics`, `drainMetrics`, and `handleMetricsTicker` as thin `Client` forwards
- [ ] 2.4 Leave `Sleep` / `Wake` / `Close` ticker + drain wiring on `Client`; `drainMetrics` still no-ops when `metricsInterval <= 0`

## 3. Tests

- [ ] 3.1 Update `zzz_metrics_test.go` helpers to construct the reporter beside the Client literal and keep `attachTestTransport` (do not edit `zzz_session_test.go`)
- [ ] 3.2 Cover window-survives-transport-replace: unsent counts still POST after `AdoptTransport`, and the request uses the new transport
- [ ] 3.3 Keep existing processed / dropped / origin / startup-timestamp / Sleep-drain / Close-drain cases green

## 4. Debt close

- [ ] 4.1 Delete `knowledge/debt/2026-09-17-metrics-reporter-split.md`
- [ ] 4.2 Mark the matching `issues.md` row `[x]` with `Taken:`

## 5. Verify

- [ ] 5.1 `go test` for `pkg/lapi` (metrics tests plus the package)
- [ ] 5.2 Grep live product paths (not `openspec/changes/archive/`, not `devstate/`) for `atomic.Pointer` and for a `*http.Client` field on the reporter
