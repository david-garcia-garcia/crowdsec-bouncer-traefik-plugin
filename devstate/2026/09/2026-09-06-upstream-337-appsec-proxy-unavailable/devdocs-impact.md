# Devdocs impact
change: appsec-proxy-unavailable-tests

## Units
- AppSec query and challenge relay — subsystem — `knowledge/devdocs/core_plugin_appsec.md` / `pkg/appsec`

## Findings
- [x] stale-usage  AppSec query — How-to named “unreachable” without HTTP 502/503/504; those statuses are the apply’s proof
  Produced: How-to bullet + Gotcha that listener 502/503/504 are unreachable (same `crowdsecAppsecFailureAction` as transport failure)
