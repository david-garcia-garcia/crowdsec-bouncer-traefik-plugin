# Devdocs impact
change: yaegi-safe-ticker-loop

## Units
- Stream single-flight — subsystem — `pkg/lapi` stream ticker (`startStreamTicker` / `runStreamTicker`); spec `core_plugin_lapi_stream-single-flight`
- LAPI usage-metrics — subsystem — `pkg/lapi` metrics ticker (`startMetricsTicker` / `runMetricsTicker`); spec `core_plugin_lapi_usage-metrics`

## Findings
- [x] stale-usage  Stream single-flight — `core_plugin_lapi_stream-single-flight` How-to still named `startTicker`; apply uses `startStreamTicker` / `runStreamTicker` and a distinct `select` from metrics
- [x] stale-usage  LAPI usage-metrics — `core_plugin_lapi_usage-metrics` How-to still named `startTicker`; apply uses `startMetricsTicker` / `runMetricsTicker` and a distinct `select` from stream
