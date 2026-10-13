# Test coverage

Ticket job (source: `devstate/requirement.md`): replace in-tree `pkg/reclaim` and `pkg/simpleredis` with traefik-middleware-utilities `v1.0.3` and migrate callers to `OpenWithHooks` / vendored SimpleRedis.

1. [hard] Edge case untested — `pkg/cache/cache.go:236-249` (`redisClientConfig`) / `Client.New` — this change adds explicit dial 2s and command 1s instead of utilities zero-Config defaults; production: `simpleredis.New(redisClientConfig(...))`; test: `Test_NewKeepsRedisReadersByPointer` in `pkg/cache/cache_test.go:169-199` only checks pointer identity after `Client.New`, not timeout fields
   → Assert the `Config` passed to `simpleredis.New` carries `DialTimeout` 2s and `CommandTimeout` 1s (or equivalent behavioral proof)
   Status: done
   Argument: Test_redisClientConfigTimeouts.

2. [hard] Critical path untested — `pkg/cache/cache.go:100-106` (`redisCache.get`) — miss mapping retargeted from `err.Error()` switch to `simpleredis.IsMiss`; test: `Test_Get` in `pkg/cache/cache_test.go:12-47` uses `localCache` only; `(none)` exercises Redis GET miss → `cache:miss`
   → Drive `Client.New` with a reachable fake Redis that returns a utilities miss and assert `Get` returns `cache:miss`
   Status: done
   Argument: Test_redisGetMissMapsCacheMiss.

3. [hard] Critical path untested — `pkg/reclaim/table.go` (upstream sync) — diff deletes `pkg/reclaim/table_test.go` (~1104 lines) and leaves only `peek_test.go`; production: full upstream table lifecycle (grace reclaim, `OpenWithHooks`, stored `Hooks`); tests: `peek_test.go:10-47`, plus LAPI integration `pkg/lapi/session_test.go:153-185` and `plugin_test.go:209-262` — no unit or integration test targets `pkg/appsec/session.go` `OpenWithHooks` reclaim (AppSec is in scope per proposal)
   → Port focused upstream table tests for `OpenWithHooks`/grace, or add an AppSec session reclaim test mirroring LAPI grace/ticker behavior
   Status: done
   Argument: OpenWithHooks grace test plus TestOpen_ReclaimsSameClient.

4. [judgement] Happy path only — `pkg/cache/cache.go:196-199` — per-reader `simpleredis.New` failure logs and `continue`; test: `(none)`
   → Assert `Client.New` with one invalid read host still builds a cache with the writer and valid readers
   Status: skipped
   Argument: judgement; invalid-reader skip is outside the ticket job.
