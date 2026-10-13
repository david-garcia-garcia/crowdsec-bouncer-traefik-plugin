# Devdocs impact
change: split-connection-files

## Units
- CrowdsecConnection — subsystem — `pkg/crowdsecconnection/` / Language on `core_plugin_middleware.md`
- AppSec query — subsystem — `CrowdsecConnection.AppsecQuery` / `core_plugin_appsec.md`
- Decision stream and live lookup — subsystem — `core_plugin_decisionscope.md` Key files

## Findings
- [x] stale-usage  AppSec query — `core_plugin_appsec.md` Key files still names only `connection.go`
- [x] stale-usage  Decision stream and live lookup — `core_plugin_decisionscope.md` Key files still names `connection.go` for stream/live
