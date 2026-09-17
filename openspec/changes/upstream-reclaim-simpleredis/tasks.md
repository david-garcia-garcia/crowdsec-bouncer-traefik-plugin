## 1. Vendor utilities SimpleRedis

- [ ] 1.1 `go get github.com/david-garcia-garcia/traefik-middleware-utilities@v1.0.3` and `go mod vendor`
- [ ] 1.2 Point `pkg/cache` at the vendored module: `New(Config)` with dial 2s / command 1s, commands with `context.Background()`, `IsMiss` / `IsUnreachable` (or equal strings)
- [ ] 1.3 Delete `pkg/simpleredis`
- [ ] 1.4 Adapt `pkg/cache` tests that constructed `SimpleRedis` via `Init`

## 2. Source-sync reclaim and migrate callers

- [ ] 2.1 Replace `pkg/reclaim` table sources with utilities `reclaim/` at `v1.0.3` (keep package path)
- [ ] 2.2 Keep or rewrite `Default`, `Peek`, `PeekLivePrefix`, `View`, and a test reset that can install a zero-grace table
- [ ] 2.3 Process table grace is `ReclaimGraceDuration` (30s). Remove `OpenWithGrace` and `*Wrapped`
- [ ] 2.4 `pkg/lapi/session.go` and `pkg/appsec/session.go` pass `Hooks`. `plugin_test.go` / session tests use the new reset helper

## 3. Specs and usage

- [ ] 3.1 Add `openspec/specs/core_cache_redis_utilities-client/spec.md` from this change; delete `openspec/specs/core_cache_redis_in-tree-client/`
- [ ] 3.2 Apply fold deltas to `std_go_reclaim_context-lease`, `core_plugin_appsec_client`, `core_plugin_middleware_instance-reclaim`
- [ ] 3.3 Update `knowledge/devdocs/core_cache_redis.md` and `knowledge/devdocs/std_go_reclaim.md`

## 4. Verify

- [ ] 4.1 `go test` for `pkg/cache`, `pkg/reclaim`, `pkg/lapi`, `pkg/appsec`, and root plugin tests
- [ ] 4.2 Grep live product paths (not `openspec/changes/archive/`, not `devstate/`) for `pkg/simpleredis` and `reclaim.Wrapped` / `OpenWithGrace`
