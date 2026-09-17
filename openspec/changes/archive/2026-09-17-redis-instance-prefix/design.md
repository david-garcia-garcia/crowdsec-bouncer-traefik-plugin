## Context

See `proposal.md`. Today `lapi.CachePrefix` for stream/alone is `SessionHex` (LAPI URL+key only); `client_stream.handleStreamCache` skips LAPI when `Get("updated")` succeeds. Multi-pod Redis therefore shares one lease and remediation namespace. CrowdSec assigns `stream_cursor` per bouncer row (key hash + LAPI-visible IP). Explore decisions in `devstate/explore.md` fix prefix-only isolation; reclaim `SessionKey` stays unchanged.

## Goals / Non-Goals

**Goals:**
- Compute stable effective instance id once per Client construction path (config → hostname → fallback).
- Extend `CachePrefix` to `{hexBase}:{instanceId}` for all Redis-backed LAPI modes.
- Validate `redisCacheInstanceId` alongside existing Redis fields when enabled.
- Unit tests for prefix shape, validation, and cross-instance lease isolation.

**Non-Goals:**
- Removing Redis, PR #59 direction, or captcha/AppSec/reclaim redesign.
- Embedding instance id in `streamSession`, `SessionPrefix`, or `SessionKey`.
- Changing how LAPI selects bouncer rows.

## Decisions

1. **Config field** `redisCacheInstanceId` on existing Configuration struct; validate in Prepare/validate when `redisCacheEnabled` (explore assumed rules).
2. **Resolution owner** `pkg/lapi` reads configured id from config passed into Client construction; resolves hostname/fallback when blank; reuse one helper for all `CachePrefix` calls—no per-request hostname reads.
3. **Prefix shape** `{SessionHex or IdentityHex}:{sanitizedInstanceId}` with single colon; operator id used as-is when valid (no hash for 128-char limit).
4. **Reclaim unchanged** Cross-pod isolation is Redis prefix only; in-process warn-and-wire keeps one Client per `SessionPrefix`+settings hash.
5. **Devdocs** Update `knowledge/devdocs/core_cache_redis.md` during implement to state LAPI cursor vs Redis instance cache (spec requirement covers behavior; devdocs cover usage).

## Risks / Trade-offs

- [Hostname changes on pod reschedule without explicit id] → Operators should set `redisCacheInstanceId` to pod name via downward API for stable keys; document in devdocs.
- [Legacy multi-pod Redis without instance id] → Keys remain shared until operators set instance id; intentional—fixes require explicit or hostname-based identity.
- [`unknown-instance` fallback collides if many hosts fail hostname] → Rare; Warn surfaces; operators can set explicit id.

## Migration Plan

Deploy with optional `redisCacheInstanceId`. Single-pod installs with unique hostnames get automatic isolation. Multi-pod Redis: set pod name in config; existing shared keys may be orphaned (remediations refresh from LAPI). Rollback is revert; no schema migration.

## Open Questions

None — explore assumed policies apply.
