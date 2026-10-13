## Why

On `master` the Redis cache depends on published `simpleredis` v1.0.12: one TCP dial per command, inline protocol, and no `MGet`. Real-stack e2e never talks to a functional Redis-protocol backend. [simpleredis PR #8](https://github.com/maxlerebourg/simpleredis/pull/8) is untagged; Yaegi/localPlugins cannot `replace` to that branch.

## What Changes

- Copy PR #8 (`pool-redis-connections`, HEAD `f8801cc`) into `pkg/simpleredis` as a first-party package. Drop `github.com/maxlerebourg/simpleredis` from `go.mod`, `vendor/`, and depguard.
- Hold pooled clients by pointer in `pkg/cache` so the mutex is not copied.
- Teach mock e2e `serveRedis` to parse RESP arrays so `make e2e_mock` still passes.
- Add Dragonfly (`docker.dragonflydb.io/dragonflydb/dragonfly:v1.40.2`) to the Pester real-stack compose and cover live-mode Redis cache against it.
- Do not call `MGet` from `pkg/cache` yet. Do not rewrite `examples/redis-cache/`.

## Capabilities

### New Capabilities

- `core_cache_redis_in-tree-client`: in-tree pooled SimpleRedis (PR #8 API) used by the plugin cache; published module removed.
- `build_e2e_mock_redis-resp`: mock LAPI Redis stand-in understands RESP arrays (and still accepts inline GET).

### Modified Capabilities

- `build_e2e_pester_crowdsec-stack`: real-stack compose includes Dragonfly; Pester covers a functional Redis-protocol cache path with client identity only via `X-Forwarded-For`.

## Impact

- `pkg/simpleredis/` (new), `pkg/cache/cache.go`, `pkg/cache/cache_test.go`
- `go.mod` / `go.sum` / `vendor/github.com/maxlerebourg/simpleredis/`
- `.golangci.yml` depguard
- `tests/e2e/mock/mocklapi/main.go`
- `tests/e2e/real/docker-compose.test.yml`, new `tests/e2e/real/*.Tests.ps1`
- `openspec/specs/domains.md` gains `core` / `cache`
- Plugin public config keys (`redisCache*`) unchanged. Not **BREAKING**.
