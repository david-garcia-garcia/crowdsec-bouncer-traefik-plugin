# Devdocs impact
change: shared-decision-store

## Units
- DecisionStore — subsystem — `pkg/lapi/decisionstore.go` / `core_cache_client.md`
- Redis cache client — subsystem — `pkg/cache/acquire.go` / `core_cache_redis.md`
- Stream lease — pattern — `pkg/lapi/client_stream.go` / `core_plugin_lapi_stream-lease`
- LAPI reclaim key — pattern — `pkg/lapi/session.go` / `core_plugin_lapi_reclaim-key.md`
- Reclaim context lease — pattern — `pkg/reclaim` / `std_go_reclaim.md`
- Plugin middleware New — subsystem — `plugin.go` / `core_plugin_middleware.md`

## Findings
- [x] missing-packet  Stream lease — no packet; only How-to bullets on `core_cache_client.md` and `core_cache_redis.md`
- [x] stale-usage  Redis cache client — How-to still names deleted `CachePrefix`; Key files omit `pkg/cache/acquire.go`
