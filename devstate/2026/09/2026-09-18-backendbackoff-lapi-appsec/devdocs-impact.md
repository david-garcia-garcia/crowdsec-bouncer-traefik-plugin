# Devdocs impact
change: backendbackoff-lapi-appsec

## Units
- LAPI backendbackoff Gate — subsystem — `pkg/lapi`, spec `core_plugin_lapi_backend-backoff`
- AppSec backendbackoff Gate — subsystem — `pkg/appsec`, spec `core_plugin_appsec_backend-backoff`
- Config validation — subsystem — `pkg/configuration`, spec `core_plugin_middleware_config-validation`
- LAPI connection — subsystem — `pkg/lapi` LiveLookup / Close, `core_plugin_lapi_connection`
- LAPI reclaim key — subsystem — `pkg/lapi/identity.go`, `core_plugin_lapi_reclaim-key`
- AppSec challenge — subsystem — `pkg/appsec` Query, `core_plugin_appsec`
- Plugin middleware New — subsystem — `pkg/bouncer` LiveLookup call, `core_plugin_middleware`

## Findings
- [x] stale-usage  LAPI connection — LiveLookup How-to and snippet omit inbound request Context
- [x] stale-usage  LAPI reclaim key — first-wins / not-on-key lists omit backend backoff knobs
- [x] stale-usage  AppSec challenge — Query How-to omits Gate admit-before-Do; reclaim-key gotcha omits backoff knobs
- [x] stale-usage  Plugin middleware New — LiveLookup How-to omits inbound request Context
