## Why

Multi-replica Traefik with `redisCacheEnabled` shares one Redis namespace keyed only by LAPI URL and API key (`SessionHex`). The stream poll lease key `updated` then skips LAPI for every replica that sees another replica’s lease, but CrowdSec’s stream cursor is per bouncer row (hashed API key plus outbound IP LAPI sees). Shared Redis makes replicas miss stream deltas and contradicts LAPI semantics.

## What Changes

- Remove `redisCacheEnabled`, Redis/Dragonfly connection fields, `redisCacheUnreachableBlock`, and all `simpleredis` cache wiring from configuration, LAPI client construction, `pkg/cache`, and bouncer unreachable handling.
- Keep the per-`Client` in-memory TTL map as the only cache backend; stream lease `updated` stays in-process (warn-and-wire unchanged).
- Retire Redis operator examples, README sections, mock RESP e2e scenario, and real-stack Dragonfly cache proof.
- Document in OpenSpec and `knowledge/devdocs/` why Redis was removed (LAPI cursor per key+IP; shared `SessionHex` Redis broke replica polling).
- **BREAKING** for deployments that relied on Redis for cross-replica decision sharing or stream lease.

## Capabilities

### New Capabilities

- (none)

### Modified Capabilities

- `core_cache_client_isolated-store`: Memory-only isolated store; remove Redis prefix and cross-host requirements; document LAPI cursor rationale.
- `core_cache_redis_utilities-client`: Retire entire capability (plugin no longer ships a Redis cache client).
- `build_e2e_mock_redis-resp`: Retire mock Redis RESP stand-in requirement tied to plugin Redis cache.
- `build_e2e_pester_crowdsec-stack`: Remove Dragonfly Redis-protocol cache and live-mode Redis proof from the real stack.
- `core_plugin_middleware_instance-reclaim`: Drop Redis host from stream settings diff and related scenario.
- `core_plugin_decisions_scopes`: Reword Range/redis-replica scenarios for memory-only per process (no shared Redis replica skip).

## Impact

- `pkg/cache/`, `pkg/configuration/`, `pkg/lapi/`, `pkg/bouncer/`
- `go.mod` / `vendor/` when `traefik-middleware-utilities/simpleredis` is unused
- `examples/`, `tests/e2e/`, `README.md`, `knowledge/devdocs/` cache packets
- Operator configs with `redisCache*` keys (invalid after upgrade)
