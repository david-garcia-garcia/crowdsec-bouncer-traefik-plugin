# Explore
IssueKey: 2026-09-17-redis-instance-prefix

## Concepts

**LAPI stream cursor (CrowdSec):** One `stream_cursor` per **bouncer database row** (SHA-512 of `X-Api-Key` + `ClientIP()` as LAPI sees it). Pods with distinct outbound IPs get distinct rows and distinct cursors. Owner: `knowledge/research/ext_crowdsec_lapi_stream-cursor/notes.md`. This plugin does **not** change how LAPI picks the row.

**Redis cache (this plugin):** Durable/off-heap store for remediations and the stream poll **lease** (`handleStreamCache` logical key `updated`). Today `CachePrefix` for stream/alone is `SessionHex` (LAPI URL+key only), so all pods sharing one Redis and one LAPI session share one `updated` key — one pod holds the lease, others hit `alreadyUpdated` and skip LAPI while hydrating shared remediation keys. That inverts the per-IP LAPI cursor model. Owner: `pkg/lapi/client_stream.go`, `pkg/lapi/session.go`; usage: `knowledge/devdocs/core_cache_redis.md`.

**In-process reclaim (same pod):** `SessionPrefix` / `SessionKey` are **process-local** (`pkg/reclaim`). Warn-and-wire merges middlewares on one Traefik process into one `*lapi.Client` and one ticker. Owner: `knowledge/devdocs/std_go_reclaim.md`, `pkg/lapi/session.go` `OpenStream`.

```
  Pod A (hostname pod-a)              Pod B (hostname pod-b)
  ┌─────────────────────────┐        ┌─────────────────────────┐
  │ reclaim: one Client     │        │ reclaim: one Client     │
  │ CachePrefix =           │        │ CachePrefix =           │
  │  sessionHex + instanceA │        │  sessionHex + instanceB │
  └───────────┬─────────────┘        └───────────┬─────────────┘
              │                                  │
              └────────────┬─────────────────────┘
                           ▼
                    ┌─────────────┐
                    │    Redis    │  separate `updated` + remediation keys
                    └─────────────┘
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
         LAPI row (key+IP_A)       LAPI row (key+IP_B)
         own stream_cursor         own stream_cursor
```

**Operator knob:** Keep `redisCacheEnabled` (+ host/password/db/read hosts) as the only memory-vs-Redis switch. Instance scoping is a **prefix dimension**, not a second enable flag.

## Decisions

- Do **not** remove Redis or revive PR #59’s direction. Fix is prefix/isolation.
- Do **not** add a parallel Redis enable flag. Instance identity rides alongside existing Redis settings.
- Extend **Redis `CachePrefix`** (stream/alone at minimum; same instance suffix when live/none use Redis) with a stable **instance identity**: optional `redisCacheInstanceId`; when empty after trim, `os.Hostname()`; document fallback when hostname fails (see Open questions).
- Prefix shape for propose: `{SessionHex or live IdentityHex base}:{sanitizedInstanceId}` (exact separator and sanitization in implement/spec). Same LAPI session + same instance → same prefix (warn-and-wire on one process still one Client, one prefix).
- Do **not** put instance id into `streamSession`, `SessionPrefix`, or `SessionKey` / `streamSettings`. Reclaim never crosses pods; adding instance there would not fix Redis and could confuse in-process wiring.
- **Spec/devdocs (propose/implement):** Document explicitly that LAPI stream progress is keyed by CrowdSec bouncer row (API key hash + LAPI-visible client IP); Redis is per-bouncer-**instance** durable cache for that row’s consumer, not a cross-replica stream bus or shared LAPI cursor. Update `core_cache_redis.md` and related spec leaves.
- Preserve SimpleRedis, Dragonfly e2e, captcha HMAC cookie path, reclaim warn-and-wire semantics.
- Closed PR #59 (remove-redis-cache) remains rejected; this ticket is prefix-only.

## Reproduction

**Not reproduced** in this run (no multi-pod Redis stack executed). **Confirmed by code trace:** `CachePrefix` → `SessionHex` only for stream/alone; `handleStreamCache` skips LAPI when `Get("updated")` succeeds (`client_stream.go`). Aligns with requirement and `ext_crowdsec_lapi_stream-cursor` (distinct LAPI rows per pod IP).

## Open questions

- Q: Exact config field name and validation for optional instance id?
  Decision: assumed — JSON/map key `redisCacheInstanceId` (matches `redisCache*` family). Optional string: trim outer space; reject if longer than 128 runes after trim; allow `[A-Za-z0-9._-]+` only when non-empty; omit/empty after trim → hostname path. No second enable flag. Validate in `configuration` Prepare/validate alongside other Redis fields when `redisCacheEnabled`.
  By: explore

- Q: Hostname fallback when `os.Hostname()` fails in a container?
  Decision: assumed — use fixed literal `unknown-instance`, log one `Warn` with the error, document in devdocs. Do not generate a random per-start id (would break Redis continuity on restart within the same pod).
  By: explore

- Q: Must `streamSettings` / reclaim `SessionKey` include instance id so warn-and-wire never merges pods?
  Decision: assumed — no. Reclaim table is in-process only; pods never share `SessionKey`. Cross-pod isolation is solely `CachePrefix` + Redis. In-process warn-and-wire stays on `SessionPrefix` + settings hash unchanged.
  By: explore

- Q: Who owns bouncer instance identity for the Redis prefix?
  Decision: assumed — operator supplies `redisCacheInstanceId` in Traefik plugin config (`pkg/configuration`); when unset/blank, `pkg/lapi` resolves effective id via `os.Hostname()` (or fallback above) when computing `CachePrefix`. Reuse that function everywhere Redis `keyPrefix` is built; do not re-read hostname per request. K8s pod name via downward API is operator wiring into `redisCacheInstanceId`, not a built-in owner.
  By: explore

- Q: Should live/none modes get the same instance suffix on `CachePrefix` when Redis is enabled?
  Decision: assumed — yes. Any Redis-backed LAPI Client on two pods with identical config still collides today on `IdentityHex` alone. Append the same instance identity to the live/none prefix base so all Redis remediations are pod-scoped consistently.
  By: explore

- Q: How should instance id appear in the Redis key prefix (encoding)?
  Decision: assumed — append sanitized effective instance id after the existing hex base with a single `:` separator; if sanitization would empty an operator-provided id, treat as validation error. Do not hash the instance id unless a future id exceeds Redis key limits (128-char knob makes hashing unnecessary).
  By: explore
