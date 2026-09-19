# Devdocs impact
change: split-http-timeouts

## Units
- LAPI connection — subsystem — pkg/lapi/client_http.go
- AppSec challenge — subsystem — pkg/appsec/client_http.go
- LAPI reclaim key — subsystem — core_plugin_lapi_reclaim-key
- Plugin middleware New — subsystem — pkg/bouncer/bouncer.go
- Config validation — subsystem — pkg/configuration/configuration.go

## Findings
- [x] language-gap  Config validation — `core_plugin_middleware_config-validation` has How-to for `EffectiveHTTPTimeoutSeconds`, no Language term
- [x] stale-usage  AppSec challenge — `core_plugin_appsec` Gotcha names only `HTTPTimeoutSeconds` on the AppSec reclaim key
- [x] stale-usage  LAPI reclaim key — `core_plugin_lapi_reclaim-key` Gotcha says "HTTP timeout"; spec names the three inherit knobs
