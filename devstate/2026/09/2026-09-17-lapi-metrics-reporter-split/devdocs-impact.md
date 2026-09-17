# Devdocs impact
change: extract-metrics-reporter

Pin: origin/master `2a7b6b100fabedad399d302a9269e75da2de68cf`...HEAD excluding `devstate/` and `.cursor/` (after Sync). Code-review SHA `e6cc9abaa0e9246398cd82fa2273fbe320f0185d` would include the AppSec merge; override with that SHA to re-pin.

## Units
- LAPI usage-metrics — subsystem — `knowledge/devdocs/core_plugin_lapi_usage-metrics.md`
- LAPI connection — subsystem — `knowledge/devdocs/core_plugin_lapi_connection.md`

## Findings
- [x] stale-usage  LAPI usage-metrics — Overview still says the Client ticker POSTs; How-to stamps `startedAt` on `New`; no MetricsReporter owner, query bind, or `attachTestMetricsReporter` seam
