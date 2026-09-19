# Devdocs impact
change: appsec-query-hardening

## Units
- AppSec Client — subsystem — `pkg/appsec` / spec `core_plugin_appsec_client` / `knowledge/devdocs/core_plugin_appsec.md`
- AppSec FailureAction — pattern — spec `core_plugin_appsec_failure-action` / `knowledge/devdocs/core_plugin_appsec.md`

## Findings
- [x] stale-usage  AppSec Client — How-to already covers drain, limit `0`, FailureAction on read, Content-Length, and DELETE; Key files omitted `query.go`; Gotchas omitted `errors.Is` classification of response-body io vs oversized
