## Why

On `master`, `pkg/reclaim` and `pkg/simpleredis` are ad-hoc copies that already drift from traefik-middleware-utilities `v1.0.3` (Hooks vs `*Wrapped`, `New(Config)` vs `Init`, commands with `context.Context`). Bugfixes and Yaegi hardening land twice.

## What Changes

- Require `github.com/david-garcia-garcia/traefik-middleware-utilities v1.0.3` and vendor it (same GOPATH rule as `golang-ttl-map`).
- Delete `pkg/simpleredis`. Cache imports the vendored module: `New(Config)` with this plugin’s dial 2s / command 1s, `Get`/`MGet`/`Set`/`Del` with `context.Background()`.
- Replace `pkg/reclaim` sources with upstream `reclaim/` (same import path). Keep product `Default`, `Peek`, `PeekLivePrefix`, `View`, and test reset on that package. Call sites pass `Hooks` instead of `*Wrapped`. Process table grace is `ReclaimGraceDuration` (30s); drop `OpenWithGrace`.
- Rename live spec `core_cache_redis_in-tree-client` → `core_cache_redis_utilities-client` (the old leaf names the deleted package).
- Not **BREAKING** for operators. Redis keys, reclaim keys, and Traefik config stay.

## Capabilities

### New Capabilities

- `core_cache_redis_utilities-client`: Redis cache uses the vendored utilities SimpleRedis client, not `pkg/simpleredis` and not `maxlerebourg/simpleredis`.

### Modified Capabilities

- `std_go_reclaim_context-lease`: Open takes `Hooks`; no `*Wrapped` or `OpenWithGrace`; Peek APIs stay on `pkg/reclaim`.
- `core_plugin_appsec_client`: AppSec create passes `Hooks`; wait is the process-table 30s grace.
- `core_plugin_middleware_instance-reclaim`: LAPI create passes `Hooks`; wait is the process-table 30s grace (no 10s `DefaultGrace` vs 30s put).

## Impact

- `go.mod`, `go.sum`, `vendor/`
- `pkg/simpleredis/` (removed)
- `pkg/reclaim/`, `pkg/cache/`, `pkg/lapi/session.go`, `pkg/appsec/session.go`, `plugin_test.go`
- `openspec/specs/core_cache_redis_in-tree-client/` (removed)
- `openspec/specs/core_cache_redis_utilities-client/` (added)
- `knowledge/devdocs/core_cache_redis.md`, `knowledge/devdocs/std_go_reclaim.md`
