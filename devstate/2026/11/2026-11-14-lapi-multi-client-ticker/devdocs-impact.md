# Devdocs impact
change: isolate-lapi-poll-loops-across-clients

## Units
- Poll timer — pattern — `pkg/lapi/poll_timer.go` (`pollTimer`, `startPollTimer`); spec `core_plugin_lapi_stream-single-flight` "Stream poll is single-flight per DecisionStore session"
- Usage-metrics loop lifecycle — subsystem — spec `core_plugin_lapi_usage-metrics` "Usage-metrics share the Client reclaim lifetime"

## Findings
- [x] language-gap  Poll timer — `core_plugin_lapi_stream-single-flight` had How-to, Gotchas and Key files for `pollTimer` (updated in implement) but no Language term. Produced: term **Poll timer** with _Avoid_ ticker loop, `select` loop, stop channel.
- [x] stale-usage  Usage-metrics loop lifecycle — `core_plugin_lapi_usage-metrics` How-to and Gotcha named `startMetricsTicker` / `stopTicker` and the distinct-`select` rule. Updated in implement to `startPollTimer` / `pollTimer.stop`, no `select`.
