## Context

See `proposal.md` Why. `origin/master` vendors `github.com/maxlerebourg/simpleredis` v1.0.12 and copies `SimpleRedis` by value in `pkg/cache`. Mock `serveRedis` reads inline GET. Real-stack compose has no Redis-protocol process.

Client IP owner: Traefik `forwardedHeaders` plus plugin `forwardedHeadersTrustedIps`. Cache key is that IP. Tests send `X-Forwarded-For` only.

PR #8 pin: `maxlerebourg/simpleredis@f8801cc` on `pool-redis-connections`. Dragonfly pin: `docker.dragonflydb.io/dragonflydb/dragonfly:v1.40.2` (GET/SET EX/DEL/MGET/AUTH/SELECT supported; SET gaps are unused IF* conditionals).

## Goals / Non-Goals

**Goals:**
- In-tree PR #8 client under `pkg/simpleredis`; cache holds pointers; published module gone.
- Mock Redis understands RESP.
- Pester real-stack covers a functional Dragonfly cache.

**Non-Goals:**
- Calling `MGet` from `pkg/cache`.
- Honouring Range/Country/AS scopes.
- Replacing `examples/redis-cache/` with Dragonfly.
- Merging upstream simpleredis PR #8.
- Changing `redisCache*` operator keys.

## Decisions

1. **Copy, do not `replace`.** Yaegi loads the bind-mounted module tree. An untagged GitHub `replace` is not a plugin source.
2. **`pkg/simpleredis`.** Same `pkg/` layout as cache/captcha. Apache-2.0 LICENSE travels with the copy. Keep PR #8 tests that do not need a live Redis (in-process fake).
3. **Pointers.** `writer *simpleredis.SimpleRedis` and `readers []*simpleredis.SimpleRedis`.
4. **Mock RESP.** Parse `*n` arrays in `serveRedis`; keep inline GET for the old traces.
5. **Dragonfly in real-stack only.** Not in mock e2e. Image `v1.40.2`, memlock -1, no requirepass.
6. **Restart Traefik to prove Dragonfly.** After a cached ban, restart `traefik-test`; a still-forbidden request cannot be explained by the process-local TTL map.

## Risks / Trade-offs

- [Dragonfly `v1.40.2` tag missing on the registry] → Confirm pull during implement; fall back to the digest of that release if the name tag is absent.
- [Traefik restart flakes in CI] → Wait for Traefik ready the same way `Test-Integration.ps1` already does; bound timeout.
- [Yaegi and `sync.Mutex` / deadlines] → PR #8 claims `yaegi test` passed; this repo already runs `make yaegi_test` in Main.

## Migration Plan

No operator config change. Merge replaces the vendored module with `pkg/simpleredis`. Rollback is revert. Existing `redisCacheHost` deployments keep working against Redis or Dragonfly.
