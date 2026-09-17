## Why

With `redisCacheEnabled`, multiple Traefik pods that share one Redis but use distinct outbound IPs each need their own LAPI stream poll and remediation cache. Today `CachePrefix` is only the LAPI session hex (URL+key), so every pod shares the stream lease key `updated` and remediation keys—one pod holds the lease while others skip LAPI and hydrate stale shared state, inverting CrowdSec’s per–bouncer-row stream cursor (API key hash + LAPI-visible client IP).

## What Changes

- Add optional Traefik config `redisCacheInstanceId`; when empty after trim, resolve effective instance id from `os.Hostname()` (fallback `unknown-instance` with one Warn if hostname fails).
- Extend `lapi.CachePrefix` for all Redis-backed modes (stream/alone and live/none) to `{existingHexBase}:{sanitizedInstanceId}` so each pod/process has an isolated Redis key space while warn-and-wire on one process still shares one prefix.
- Validate `redisCacheInstanceId` when Redis is enabled: trim; max 128 runes; when non-empty allow `[A-Za-z0-9._-]+` only; reject if sanitization would empty a non-empty operator value.
- Document that LAPI stream progress is owned by CrowdSec bouncer row (key + IP); Redis is durable per-instance cache for that consumer, not a cross-replica stream bus.
- Preserve SimpleRedis, Dragonfly e2e, captcha HMAC cookie, reclaim/warn-and-wire; do not add a parallel Redis enable flag or change reclaim `SessionKey` / `streamSettings`.
- **Not BREAKING** for single-pod deployments with unique hostnames; shared Redis without instance id today already collides across pods—operators with multi-pod Redis should set `redisCacheInstanceId` (e.g. pod name) for stable keys across restarts.

## Capabilities

### New Capabilities

- (none)

### Modified Capabilities

- `core_cache_client_isolated-store`: Redis prefix SHALL include bouncer instance identity; optional `redisCacheInstanceId`; stream lease and remediations isolated per instance on shared Redis; LAPI cursor vs Redis role documented at requirement level.

## Impact

- `pkg/lapi/session.go` (`CachePrefix`, effective instance id resolution)
- `pkg/configuration/configuration.go` (new field + validation)
- `pkg/lapi/client.go`, tests in `pkg/lapi/`, `pkg/cache/`, `pkg/configuration/`
- `knowledge/devdocs/core_cache_redis.md` (implement/devdocs phase)
- `openspec/specs/core_cache_client_isolated-store/spec.md`
