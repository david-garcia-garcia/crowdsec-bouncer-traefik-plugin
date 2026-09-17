# Explore
IssueKey: 2026-09-17-remove-redis-cache

## Concepts

**Isolated cache Client** (usage `core_cache_client`): one `pkg/cache.Client` per LAPI Client. Memory is a private TTL map on that Client. Today Redis adds a prefixed key space (`CachePrefix` / `SessionHex` for stream/alone, `IdentityHex` for live/none).

**Stream poll lease** (`cacheTimeoutKey` = `updated` in `pkg/lapi/client_stream.go`): `handleStreamCache` GETs `updated` first. Hit → skip LAPI, hydrate range membership. Miss → SET lease TTL `max(updateInterval-1, 1)`, fetch `/v1/decisions/stream`, apply decisions into the same Client’s map.

**SessionHex** (`pkg/lapi/session.go`): FNV hash of LAPI URL + API key (+ mode fields in `streamSession`). Used as the memory/Redis prefix so warn-and-wire siblings on one CrowdSec row share one cache Client and one lease.

**Warn-and-wire** (`pkg/reclaim` + `OpenStream` in `session.go`): one stream ticker per LAPI row (same outbound IP LAPI sees). `PeekLivePrefix(SessionPrefix)` blocks a second poller when settings disagree; first router wins. Unchanged by this ticket.

**LAPI stream cursor owner** (research `knowledge/research/ext_crowdsec_lapi_stream-cursor/notes.md`): cursor lives on the **bouncer DB row** for hashed API key + **client IP LAPI sees** (Traefik pod outbound, not visitor XFF). Same key + different outbound IPs → different rows → each must poll its own stream. Shared Redis under `SessionHex` (key only) makes replica B treat replica A’s `updated` as its own lease and **skip LAPI** while its CrowdSec row is stale.

```
DestBranch failure (redisCacheEnabled, two replicas, distinct LAPI rows)

  Replica A ──poll──► LAPI (cursor row A)
       │
       └── SET SessionHex:updated ──► Redis ◄── GET hit ── Replica B
                                              (skips LAPI, row B stale)

Target (this change)

  Each process: memory map per LAPI Client only
  Replica A ──poll──► LAPI row A     Replica B ──poll──► LAPI row B
  In-process warn-and-wire still dedupes tickers on same row + same process
```

**Redis surface today**: `configuration` (`redisCacheEnabled`, host/read hosts, password, database, `redisCacheUnreachableBlock`), `cache.Client.New(..., isRedis, ...)`, `simpleredis` in vendor, bouncer fail-closed on unreachable cache, examples/README/e2e (mock RESP stand-in, real Dragonfly stack).

**Reproduction (explore)**: Not run as a multi-replica Redis stack in this phase. **Reproduced by code trace**: `handleStreamCache` skips LAPI on any cache hit for `updated`; with Redis enabled, all replicas sharing `SessionHex` share that key regardless of LAPI row. Aligns with `knowledge/research/ext_crowdsec_lapi_stream-cursor/notes.md` (per-IP bouncer rows). Existing unit tests (`pkg/lapi/zzz_client_stream_test.go`) prove in-process lease hit/miss only (memory), not cross-replica Redis.

## Decisions

- **Remove Redis completely** — stream, live, and `redisCacheUnreachableBlock`; no live-only or “Redis without lease” mode.
- **Keep per-Client in-memory TTL map** as the only cache backend (`localCache` path in `pkg/cache/cache.go`).
- **Keep in-process warn-and-wire** — one stream ticker per LAPI URL+key row via reclaim; do not add cross-process lease or shared store.
- **Do not change CrowdSec LAPI bouncer identity** (outbound IP / row selection; issue 3726 out of scope).
- **Explain removal in OpenSpec + `knowledge/devdocs/`** during propose/implement/devdocsimpact: LAPI cursor is key+outbound IP; shared `SessionHex` Redis broke replica polling and falsely implied shared remediations across replicas.
- **Breaking change accepted** for operators using Redis for horizontal decision sharing; each replica holds its own remediations and must poll its own LAPI row.
- **Retire Redis-specific spec leaves and e2e** in the same change (layer removal = take, not debt note): `core_cache_redis_utilities-client`, Redis clauses in `core_cache_client_isolated-store`, `build_e2e_mock_redis-resp`, redis sections in `build_e2e_pester_crowdsec-stack`; drop `examples/redis-cache/`, mock `scenarios/redis/`, real `redis_cache.Tests.ps1` wiring.
- **Drop `simpleredis` from product imports** when `pkg/cache` no longer uses it; run `go mod vendor` so vendor tree matches (mocklapi inline RESP stand-in may remain until scenario deleted).
- **Captcha grace** stays HMAC cookie (`core_plugin_middleware_captcha-gate`); no Redis path.

## Open questions

- Q: Do we remove Redis for live/none modes as well as stream, or only stop sharing stream lease?
  Decision: assumed — remove all Redis cache wiring and config; live uses memory-only per Client like stream after this change.
  By: explore

- Q: After removal, how do multi-replica deployments get consistent ban state?
  Decision: assumed — each replica polls LAPI for its own bouncer row and caches locally; operators use one outbound IP per CrowdSec row or accept per-replica memory (no shared Redis). Document in devdocs/spec, do not reintroduce shared store.
  By: explore

- Q: Do any downstream forks rely on Redis keys for non-stream side channels?
  Decision: assumed — none known; ticket treats removal as breaking for Redis deploys only; no compatibility shim.
  By: explore

- Q: Who owns the client IP LAPI uses for bouncer row selection?
  Decision: assumed — CrowdSec LAPI `api_key` middleware (`ClientIP()` on the HTTP connection from this plugin). Reuse documented behavior in `session.go` and research notes; this change does not alter outbound routing or headers for LAPI.
  By: explore

- Q: Should `handleStreamCache` lease logic change when Redis goes away?
  Decision: assumed — keep GET/SET `updated` on the in-memory Client; lease still dedupes polls within one process/warn-and-wire Client, no longer crosses replicas.
  By: explore

- Q: Should `SessionHex` / `CachePrefix` naming stay when Redis is gone?
  Decision: assumed — keep `SessionHex` as the in-memory prefix for stream/alone session isolation; update comments and devdocs to say memory-only (propose may tighten Language).
  By: explore

- Q: Remove Redis fields from `streamSettings` warn-and-wire diff?
  Decision: assumed — yes; joiners cannot disagree on removed keys; mixed-version configs during rollout lose Redis diff warnings (acceptable).
  By: explore

- Q: Which OpenSpec / usage artifacts must move in the same change?
  Decision: assumed — take (delete or rewrite) `core_cache_redis_utilities-client`, strip Redis requirements from `core_cache_client_isolated-store`, retire or rewrite Redis e2e specs; update `core_cache_client.md`, remove or fold `core_cache_redis.md`, refresh `index_core_cache.md` / root index blurb.
  By: explore

- Q: Can we remove the vendored `simpleredis` module entirely?
  Decision: assumed — yes once `pkg/cache` and tests drop imports; verify `go.mod` / `vendor/modules.txt` after implement; mock e2e Redis stand-in deleted with scenario, not kept for plugin path.
  By: explore
