# Requirement
IssueKey: 2026-09-17-redis-instance-prefix

## Problem
With `redisCacheEnabled`, multiple Traefik pods that share one Redis but use distinct outbound IPs each need their own LAPI stream poll and cache. Today they share one Redis key namespace per LAPI URL+key (`SessionHex`), so the `updated` lease in `handleStreamCache` lets only one pod fetch while others hydrate stale shared state — the opposite of per-pod LAPI cursors (hashed API key + client IP).

## Current (code)
- `pkg/lapi/session.go` — `CachePrefix` for stream/alone returns `SessionHex(cfg)` (hash of LAPI URL+key only); comment says warn-and-wire must share keys across middlewares on one process.
- `pkg/lapi/client.go` — `cacheClient.New(..., CachePrefix(config))` applies that prefix to all cache keys for the Client.
- `pkg/lapi/client_stream.go` — `handleStreamCache` uses global logical key `updated`; if `Get` succeeds, skips LAPI and only `hydrateRangeMembership`.
- `pkg/configuration/configuration.go` — `redisCacheEnabled`, host, read hosts, password, database exist; no instance-id knob (`not found`).
- `knowledge/research/ext_crowdsec_lapi_stream-cursor/notes.md` — LAPI `stream_cursor` is per bouncer row (hashed key + LAPI-visible client IP); different pod IPs → different rows/cursors.
- `knowledge/devdocs/core_cache_redis.md` — documents prefix as session hex so two Clients on one Redis do not collide unless they share a stream session (no pod/instance dimension).

## Desired
- Keep `redisCacheEnabled` (+ host/password/db/read hosts) as the operator’s storage choice (in-memory vs Redis); do not add a parallel enable flag.
- Scope Redis keys per bouncer **instance** (pod/process): default identity from hostname (or documented fallback) plus existing LAPI session hex; optional explicit config (e.g. `redisCacheInstanceId`) for Kubernetes pod name; empty knob → hostname.
- Same instance + same LAPI session → same prefix (in-process warn-and-wire still one Client/prefix); different hosts/pods → different prefixes; each pod polls its own LAPI stream.
- Spec/devdocs: LAPI stream identity is key+IP; Redis is durable/off-heap storage for that instance, not a cross-replica stream bus.
- Preserve SimpleRedis, Dragonfly e2e, captcha HMAC cookie, reclaim/warn-and-wire.

## Affected
- `pkg/lapi/session.go` (`CachePrefix` / session vs settings split)
- `pkg/configuration/configuration.go` (+ validation if new knob)
- `pkg/lapi/client.go`, `pkg/lapi/client_stream.go`
- `knowledge/devdocs/core_cache_redis.md` (and related spec leaves)
- Tests under `pkg/lapi/`, `pkg/cache/`, e2e if prefix behavior changes

## Out of scope
- Removing Redis or Redis-backed cache
- Changing CrowdSec LAPI bouncer row selection (key/IP)
- Captcha redesign, AppSec changes
- Replacing SimpleRedis or dropping Dragonfly e2e

## Unknowns
- Exact config field name and validation rules for the optional instance id (`redisCacheInstanceId` is caller suggestion only).
- Hostname fallback when `os.Hostname` fails in container (document vs synthetic id).
- Whether `streamSettings` / reclaim `SessionKey` must include instance id so warn-and-wire never merges pods via reclaim (likely separate from cache prefix only).

## Tensions
- `session.go` intentionally shares `SessionHex` cache across warn-and-wired middlewares on one CrowdSec row; ticket wants per-pod prefixes while keeping in-process sharing — prefix must incorporate instance id without breaking same-process wiring.
- `core_cache_redis.md` line 19 says two Clients on one Redis do not collide unless they share a stream session; multi-pod Redis today violates that intent for stream lease and remediations.
- Closed PR #59 (remove-redis-cache) is explicitly rejected; fix is prefix/isolation, not dropping Redis.
