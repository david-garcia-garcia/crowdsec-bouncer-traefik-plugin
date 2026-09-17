## Context

See `proposal.md`. Today `pkg/cache.Client.New` selects `redisCache` or `localCache`, LAPI passes Redis settings and `CachePrefix`, and `handleStreamCache` uses key `updated` on whichever backend is active. Explore fixed full removal, memory-only lease, and warn-and-wire unchanged (`devstate/explore.md`, research on LAPI stream cursor per bouncer row).

## Goals / Non-Goals

**Goals:**
- Single code path: in-memory TTL map per `cache.Client`.
- Remove configuration surface (`redisCache*`, unreachable block) and bouncer fail-closed on Redis unreachable.
- Drop `simpleredis` from product imports when unused; prune examples, e2e, README, devdocs.
- Preserve in-process stream lease and reclaim session prefix semantics (`SessionHex` as memory prefix).

**Non-Goals:**
- CrowdSec LAPI bouncer row / outbound IP selection (issue 3726).
- Captcha gate (cookie-only).
- AppSec.
- New cross-replica coordination.

## Decisions

1. **Delete Redis backend in `pkg/cache`** — Remove `redisCache` type and `isRedis` branch; simplify `Client.New` signature to memory-only parameters. Alternative: keep stub returning unreachable — rejected (dead code and config confusion).
2. **Remove unreachable-block knob** — Without Redis, cache unreachable during lookup only applies if memory map fails (it does not); drop `RedisUnreachableBlock` and bouncer branch. Alternative: generic cache unreachable — rejected (no remote cache).
3. **Keep `handleStreamCache` lease on memory Client** — GET/SET `updated` unchanged for warn-and-wire within one process. Alternative: poll every tick — rejected (regression vs interval=1 spec).
4. **Strip `streamSettings` Redis fields** — Settings hash and warn-and-wire diff no longer include Redis host/password/database/read hosts.
5. **Retire e2e layers** — Delete mock Redis scenario and Dragonfly service from real compose; remove Pester tests that assert cross-restart Redis persistence.
6. **Devdocs** — Update `core_cache_client.md`; remove or fold `core_cache_redis.md` and index entries with LAPI cursor rationale (implement/devdocsimpact).

## Risks / Trade-offs

- [Operators lose shared ban cache across replicas] → Document per-replica LAPI poll; breaking change called out in proposal.
- [Stale README/examples until implement] → Same change removes them.
- [Utilities module still in go.mod for reclaim only] → Run `go mod tidy` / vendor after import audit; do not drop module if reclaim still needs it.

## Migration Plan

Deploy upgraded plugin without `redisCache*` keys (Traefik will reject unknown keys if strict, or ignore if dynamic). Each replica repopulates from its own LAPI stream/live queries. Rollback: revert release and re-enable Redis only on older plugin version.

## Open Questions

None — explore decisions cover live/none removal and spec/devdocs scope.
