# Devdocs impact
change: appsec-transport-reclaim-split

## Units
- AppSec Client — subsystem — `pkg/appsec` / Language on `core_plugin_appsec.md` and `core_plugin_middleware.md`

## Findings
- [x] stale-usage  AppSec Client — `core_plugin_appsec.md` still says reclaim by URL+key+TLS; HTTP+auth is now `transport` on `atomic.Value`
- [x] stale-usage  AppSec Client — `core_plugin_middleware.md` Language still keys AppSec by URL+key+TLS
