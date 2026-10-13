# Devdocs impact
change: 2026-09-19-optcow-stream-lookup

## Units
- DecisionStore — subsystem — `pkg/decisionstore.Store` / `core_plugin_decisionstore_store`
- Redis SimpleRedis engine — pattern — `pkg/decisionstore/redis.go`
- Stream apply — subsystem — `core_plugin_lapi_stream-apply`
- Stream single-flight — subsystem — `core_plugin_lapi_stream-single-flight`
- Stream lease — removed unit — `core_plugin_lapi_stream-lease`
- LAPI usage-metrics — subsystem — `core_plugin_lapi_usage-metrics`
- Decision scopes — subsystem — `core_plugin_decisionscope`
- LAPI reclaim key — subsystem — `core_plugin_lapi_reclaim-key`
- Middleware New — subsystem — `core_plugin_middleware`
- Request-path Debug — pattern — `std_go_logger_debug-attrs`

## Findings
- [x] stale-usage  DecisionStore — renamed `core_cache_client.md` → `core_plugin_decisionstore.md` (engines, KindOriginString, no cache/lease)
- [x] stale-usage  Redis SimpleRedis engine — folded into `core_plugin_decisionstore.md`; deleted `core_cache_redis.md`
- [x] stale-usage  Stream lease — deleted `core_plugin_lapi_stream-lease.md` (removed unit)
- [x] stale-usage  Stream apply — Store BeginTick/Put/ApplyRangeBatch; no lease
- [x] stale-usage  Stream single-flight — dropped lease wording
- [x] language-gap  Compact decision slot — overflow origin id 0 / empty OriginName
- [x] language-gap  Range index — KindOriginString; leftover U+001F dropped
- [x] stale-usage  LAPI reclaim key — cites `core_plugin_decisionstore.md`
- [x] stale-usage  Middleware New — cites `core_plugin_decisionstore.md`
- [x] stale-usage  Request-path Debug — ServeHTTP lookup Debug, not cache.Client
