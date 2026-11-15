# Devdocs impact
change: count-challenge-drop-once

## Units
- AppSec challenge relay — subsystem — `pkg/bouncer/bouncer.go` `handleAppsecResponseServeHTTP`
- Usage-metrics dropped window — subsystem — `pkg/lapi` `IncDropped` / `IncDroppedBytes`

## Findings
- [x] stale-usage  AppSec challenge relay — `core_plugin_appsec` How to use did not say the relay skips `recordDropped` under `/crowdsec-internal/challenge/`
- [x] stale-usage  Usage-metrics dropped window — `core_plugin_lapi_usage-metrics` How to use said `IncDropped` on each remediating response, with no relay callback exception
