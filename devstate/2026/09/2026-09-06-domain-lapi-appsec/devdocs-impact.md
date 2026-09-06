# Devdocs impact
change: separate-lapi-appsec-packages

## Units
- LAPI Client — subsystem — `pkg/lapi`
- AppSec Client — subsystem — `pkg/appsec`
- Middleware New — subsystem — `plugin.go` / `pkg/bouncer`
- Isolated cache Client — subsystem — `knowledge/devdocs/core_cache_client.md`
- Redis cache — subsystem — `knowledge/devdocs/core_cache_redis.md`
- Reclaim context lease — pattern — `knowledge/devdocs/std_go_reclaim.md`
- Decision scopes — subsystem — `knowledge/devdocs/core_plugin_decisionscope.md`
- Trusted-IP lookup — subsystem — `knowledge/devdocs/core_plugin_ip.md`
- LAPI usage-metrics — subsystem — `knowledge/devdocs/core_plugin_lapi_usage-metrics.md`

## Findings
- [x] stale-usage  Isolated cache Client — `core_cache_client.md` still says Connection for the LAPI reclaim value
- [x] stale-usage  Redis cache — `core_cache_redis.md` still says two Connections on one Redis
- [x] stale-usage  Decision scopes — How-to and snippet still use `conn` instead of `lapiClient`
- [x] stale-usage  Reclaim context lease — snippet still calls `newConnection` / `conn`
- [x] stale-usage  Trusted-IP lookup — Range Helpers still sit “on the connection”
- [x] stale-usage  LAPI usage-metrics — Overview still says “the connection ticker”
