# Devdocs impact
change: one-stream-per-lapi-session

## Units
- Reclaim context lease — pattern — `pkg/reclaim` / `std_go_reclaim.md`
- Plugin middleware New — subsystem — `plugin.go` / `core_plugin_middleware.md`
- Isolated cache Client — subsystem — `pkg/cache` / `core_cache_client.md`
- Redis cache client — subsystem — `pkg/simpleredis` / `core_cache_redis.md`
- Real-stack e2e — subsystem — `tests/e2e/real` / `build_e2e_real.md`
- LAPI usage-metrics — subsystem — `pkg/crowdsecconnection/connection_metrics.go` / `core_plugin_lapi_usage-metrics.md`

## Findings
- [x] language-gap  Stream session — `core_plugin_middleware.md` has CrowdsecConnection, no Language term for the LAPI URL+key stem
- [x] stale-usage  Plugin middleware New — How-to and snippet still call `reclaim.Open` for live/none; product is `OpenLive`
- [x] stale-usage  Isolated cache Client — How-to still says pass identity hex as Redis prefix; product is `CachePrefix`
- [x] stale-usage  Redis cache client — How-to still says keys are namespaced by connection identity only
