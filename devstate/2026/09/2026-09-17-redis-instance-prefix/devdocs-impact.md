# Devdocs impact
change: redis-instance-prefix

## Units
- Isolated cache Client — subsystem — `knowledge/devdocs/core_cache_client.md` / `pkg/lapi/session.go` `CachePrefix`
- Redis cache client — subsystem — `knowledge/devdocs/core_cache_redis.md`
- Effective bouncer instance identity — pattern — `pkg/lapi/instance.go`, `redisCacheInstanceId`

## Findings
- [x] stale-usage  Isolated cache Client — Language and How-to still described hex-only `CachePrefix`; fixed to instance suffix when Redis is on
- [x] language-gap  Redis cache client — no Language term for effective instance identity; added **Effective bouncer instance identity**
- [x] stale-usage  Redis cache client — apply already updated Overview/How-to/Gotchas; verified against pinned diff
