# Devdocs impact
change: cache-accepted-semantics

## Units
- Redis cache client — subsystem — `knowledge/devdocs/core_cache_redis.md`
- DecisionStore cache — subsystem — `knowledge/devdocs/core_cache_client.md`

## Findings
- [x] stale-usage  Redis cache client — `core_cache_redis` How-to/Gotchas omit replica-only nextReader Gets, void Set, and EX-as-given
- [x] stale-usage  DecisionStore cache — `core_cache_client` How-to/Gotchas omit stream Seconds() vs liveCacheTTL
