# Requirement
IssueKey: 2026-09-17-remove-redis-cache

## Problem
Multi-replica Traefik with `redisCacheEnabled` shares one Redis key namespace keyed by `SessionHex` (LAPI URL + API key only). `handleStreamCache` treats Redis key `updated` as a cross-replica lease and skips LAPI polling when another replica set it. CrowdSec LAPI stream cursor is per bouncer row (hashed API key + client IP LAPI sees), so each replica with its own outbound IP must poll its own stream. Shared Redis makes replicas miss deltas and contradicts LAPI semantics (see `knowledge/research/ext_crowdsec_lapi_stream-cursor/notes.md`, CrowdSec issue 3726).

## Current (code)
- `pkg/configuration/configuration.go` — `redisCacheEnabled`, host/read hosts, password, database, unreachable-block defaults and JSON fields.
- `pkg/cache/cache.go` — `Client.New` chooses `redisCache` (via `github.com/david-garcia-garcia/traefik-middleware-utilities/simpleredis`) or in-memory `localCache`; Redis uses prefixed keys.
- `pkg/lapi/client.go` — passes `RedisCacheEnabled` and Redis connection fields into `cacheClient.New` with `CachePrefix(config)`.
- `pkg/lapi/session.go` — `SessionHex` / `CachePrefix` for stream/alone; Redis-related fields in `streamSettings` for warn-and-wire; comments describe Redis as multi-instance store.
- `pkg/lapi/client_stream.go` — `handleStreamCache` GET/SET `updated` before/after stream fetch; skip LAPI on cache hit.
- `pkg/lapi/identity.go` — `IdentityHex` / live cache prefix when not stream/alone.
- `pkg/bouncer/bouncer.go` — `RedisUnreachableBlock()` on cache unreachable during lookup.
- `knowledge/devdocs/core_cache_client.md`, `knowledge/devdocs/core_cache_redis.md` — document Redis sharing and operators wiring Redis.
- `openspec/specs/core_cache_redis_utilities-client/spec.md`, `openspec/specs/core_cache_client_isolated-store/spec.md`, `openspec/specs/build_e2e_pester_crowdsec-stack/spec.md`, `openspec/specs/build_e2e_mock_redis-resp/spec.md` — Redis client and e2e requirements.
- `examples/redis-cache/`, `examples/enhanced-decisions/traefik/crowdsec-bouncer.yml` — operator samples with Redis keys.
- `tests/e2e/mock/scenarios/redis/` — e2e scenario using Redis cache config.
- `README.md` — Redis cache configuration section.

## Desired
- Remove `redisCacheEnabled` and all Redis/Dragonfly/simpleredis cache wiring from configuration, LAPI client construction, cache package, bouncer unreachable handling, examples, tests, and docs.
- Each process keeps stream and live decisions only in its per-`Client` in-memory TTL map (`pkg/cache/cache.go` local path).
- Keep in-process warn-and-wire (one stream ticker per LAPI row / shared outbound IP) unchanged.
- Document in OpenSpec and `knowledge/devdocs/` why Redis was removed (LAPI cursor per key+IP, shared `SessionHex` Redis broke replica polling).
- No Redis path for live mode or captcha grace (grace stays HMAC cookie per ticket).

## Affected
- `pkg/cache/`, `pkg/configuration/`, `pkg/lapi/`, `pkg/bouncer/`
- `openspec/specs/` (cache, e2e, reclaim cross-refs)
- `knowledge/devdocs/` cache packets
- `examples/`, `tests/e2e/`, `README.md`
- `go.mod` / vendor if simpleredis dependency becomes unused

## Out of scope
- Changing CrowdSec LAPI bouncer identity or row selection (issue 3726).
- Captcha gate redesign.
- AppSec behavior.

## Unknowns
- Whether any downstream fork still depends on Redis keys for non-stream side channels (ticket assumes none; removal is breaking for Redis deploys).

## Tensions
- Ticket removes all Redis; `README.md` and `examples/redis-cache/` currently steer operators toward Redis for horizontal scale — those docs become wrong until updated in this change.
- `streamSettings` warn-and-wire today diffs Redis host fields; after removal, reload disagreements on removed keys disappear (behavior change for mixed-version configs during rollout).
- E2e and OpenSpec leaves that mandate Redis/Dragonfly proof must be retired or rewritten, not left stale.
