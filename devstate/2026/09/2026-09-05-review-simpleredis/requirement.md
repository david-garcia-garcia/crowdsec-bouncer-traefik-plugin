# Requirement
IssueKey: 2026-09-05-review-simpleredis

## Problem
The Redis communication layer (`github.com/maxlerebourg/simpleredis` v1.0.12) should be as performant and resource-efficient as possible without adding much complexity or code. The ticket asks to compare that client with the official Redis Go library, have an Opus-class analysis for leaks, races, and optimizations, allow Traefik plugin `unsafe` only when the gain is worth it, fill communication-layer test gaps, and deliver a PR with passing CI.

## Current (code)
- Redis I/O is `vendor/github.com/maxlerebourg/simpleredis/simpleredis.go` (`go.mod` require `v1.0.12`). `askRedis` dials TCP per `Get`/`Set`/`Del`, optionally sends inline `AUTH`/`SELECT`, then the command, then `defer conn.Close()`.
- Protocol is inline (`genRedisArray` joins args with spaces + `\r\n`), not RESP arrays. `tests/e2e/mock/mocklapi/main.go` `serveRedis` parses that same inline line format.
- `Set`/`Del` call `askRedis` and always `return nil` (`simpleredis.go` Set/Del). `Get` creates a `chan redisCmd` that `askRedis` does not receive from; AUTH/SELECT `waitRedis` may send on that channel with nobody listening.
- `pkg/cache/cache.go` `redisCache` holds `simpleredis.SimpleRedis` by value (`writer`, `readers`). `get` maps `RedisMiss` / `RedisUnreachable`. `set`/`delete` log errors that v1.0.12 never returns.
- `.traefik.yml` has no `unsafe` / `useUnsafe` field. CI (`.github/workflows/main.yml`) runs `make yaegi_test` against Yaegi v0.16.1 (Go 1.22).
- Tests: `pkg/cache/cache_test.go` covers local cache and `nextReader` round-robin only — no Redis wire round-trip. Vendor package has no `_test.go`. Mock e2e `tests/e2e/mock/scenarios/redis/` exercises cache routing against `serveRedis`, not a real Redis protocol server.

## Desired
- Keep the public cache/config surface unless the communication layer cannot improve without it.
- After reviewing official Go Redis (`github.com/redis/go-redis` or the current official module) versus this client, adopt the smallest durable delta that is faster and cheaper on connections/CPU/allocs, without a large new abstraction.
- Use Traefik `unsafe` only if measured (or clearly evidenced) gains justify leaving Yaegi-safe stdlib.
- Opus-class review of the chosen implementation for leaks, races, and optimizations; take the ones that stay simple and short.
- Fill unit-test gaps on the communication layer (protocol, errors, reuse, AUTH/SELECT, timeout).
- Deliver one OPEN PR to `main` with CI green and the delivery card on the PR summary.

## Affected
- `vendor/github.com/maxlerebourg/simpleredis/simpleredis.go` (or a replacement in-tree client if the published module cannot be patched — CI `go mod vendor` restores vendor).
- `pkg/cache/cache.go` import and call sites that speak Get/Set/Del (and any new batch API the client grows).
- `.golangci.yml` depguard exceptions for the Redis client module.
- Communication-layer tests (new `pkg/...` tests). Mock Redis in `tests/e2e/mock/mocklapi/main.go` only if the wire format changes.
- `.traefik.yml` only if `unsafe` is taken.

## Out of scope
- Cache policy, TTL semantics, decision value strings, replica round-robin policy, `redisCacheUnreachableBlock`.
- CrowdSec LAPI/AppSec, captcha, ban pages.
- Dragonfly/real-stack e2e and other work on sibling branch `2026-09-05-integrate-redis-backend` except as research of an already-written in-tree client.
- Replacing Redis with another backend.

## Unknowns
- Whether Yaegi can load `github.com/redis/go-redis` even with Traefik `unsafe`; what `unsafe` actually unlocks in Traefik v3.
- Whether an in-tree copy (sibling ticket already copied simpleredis PR #8 pool + RESP + `MGET` into `pkg/simpleredis`) is the intended base, versus starting from vendored v1.0.12 on `main`.
- Which official Redis Go module version is compatible with Go 1.22 / Yaegi v0.16.1.

## Tensions
- Ticket says review official Redis Go library; this plugin is a Yaegi plugin today (`make yaegi_test`). A full `go-redis` client may be incompatible regardless of `unsafe`.
- Ticket says do not add much complexity or length; pooling, RESP, pipelining, and `go-redis` pull in opposite directions.
- Sibling ticket `2026-09-05-integrate-redis-backend` (dest `master`, PR #5) already inlined a pooled RESP client. This run’s dest is `main` (`origin/HEAD`), which still vendors v1.0.12. Stacking vs independent in-tree client is an explore decision.
- `pkg/cache` stores `SimpleRedis` by value; a pooled client with a mutex must not be copied — that is communication-layer, not cache policy.
