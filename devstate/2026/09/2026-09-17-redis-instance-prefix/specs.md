# Specs (propose)

Change: `redis-instance-prefix`

## FindSpecHost verdicts

| delta | verdict | spec-id | confidence | candidates |
|-------|---------|---------|------------|------------|
| Redis prefix + instance identity + stream lease isolation on shared Redis | fold | `core_cache_client_isolated-store` | high | `core_cache_client_isolated-store`, `core_cache_redis_utilities-client`, `core_plugin_lapi_stream-lease` |
| LAPI stream cursor vs Redis durable cache (requirement-level) | fold | `core_cache_client_isolated-store` | high | same |
| Optional `redisCacheInstanceId` config | fold | `core_cache_client_isolated-store` | medium | `core_cache_client_isolated-store`, (no dedicated configuration leaf) |

## Added / modified spec ids

- **Modified (delta):** `core_cache_client_isolated-store`

## Archive (2026-09-17)

- Delta `core_cache_client_isolated-store` → folded into `openspec/specs/core_cache_client_isolated-store/spec.md` (high confidence).
- Change moved to `openspec/changes/archive/2026-09-17-redis-instance-prefix/`.
- `validate-spec-map.mjs` and `validate-artifact-names.mjs` exit 0.
