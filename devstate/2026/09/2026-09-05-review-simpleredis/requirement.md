# Requirement
IssueKey: 2026-09-05-review-simpleredis

## Problem
The Redis communication layer (`pkg/simpleredis`) should be as performant and resource-efficient as possible without adding much complexity or code. Compare it with official Go Redis, review for leaks/races/optimizations, use Traefik `useUnsafe` only if worth it, fill communication-layer test gaps, deliver a PR against `master` with CI green.

## Current (code)
- Dest is `master`. Redis I/O is in-tree `pkg/simpleredis/simpleredis.go` (copied from simpleredis PR #8 @ f8801cc, plus `Close`). Idle pool max 8, RESP arrays, `Get`/`MGet`/`Set`/`Del`, AUTH/SELECT on dial. `pkg/cache` holds `*SimpleRedis`. `CrowdsecConnection.Close` calls `cacheClient.Close`.
- After `Close`, `TestCloseDrainsIdleAndDoesNotRepool` still expects `Get` to **dial a new TCP connection** (`simpleredis_test.go` want 2 conns). `borrow` does not check `closed` before `dial`.
- Tests cover hit/miss, reuse, concurrent cap, newlines, MGET, NOAUTH, Set error, unreachable, stale retry, Close drain. Missing: AUTH success once per dial, SELECT once per dial, I/O timeout, idle-timeout eviction, `Get` after Close must not dial.
- `.traefik.yml` has no `useUnsafe`. CI Yaegi v0.16.1 / Go 1.22 (`.github/workflows/main.yml`).
- Official `github.com/redis/go-redis/v9` @ 8010edc is `go 1.24`, imports `unsafe` and `syscall` on Linux (`knowledge/research/ext_redis_go-redis`).

## Desired
- Keep the in-tree client. Do not take go-redis. Do not set `useUnsafe`.
- After Close, do not dial; return unreachable. In-flight commands may finish; sockets close on release (already true).
- Fill AUTH, SELECT, timeout, idle-timeout, and no-redial-after-Close tests.
- Small comments / names only if they stay short. No pipelining, no Redis TLS, no cache GetMany, no Dragonfly e2e.

## Affected
- `pkg/simpleredis/simpleredis.go` (`borrow` after Close).
- `pkg/simpleredis/simpleredis_test.go`.
- `pkg/simpleredis/SOURCE` if the pin note needs a local-delta line.
- Spec fold: `core_cache_redis_in-tree-client`.

## Out of scope
- Cache policy, TTL, replica round-robin, `redisCacheUnreachableBlock`, key prefix.
- CrowdSec LAPI/AppSec, captcha, ban pages.
- Replacing Redis. Taking go-redis. Setting `useUnsafe`.
- Dragonfly/real-stack e2e (already on dest).

## Unknowns
None that block: go-redis and `useUnsafe` are documented in `knowledge/research/`.

## Tensions
- Ticket asked to review official Go Redis; dest already chose an in-tree Yaegi-safe client. Taking go-redis would fight Go 1.22 + Yaegi.
- `TestCloseDrainsIdleAndDoesNotRepool` currently encodes redial-after-Close as desired; this change reverses that.
