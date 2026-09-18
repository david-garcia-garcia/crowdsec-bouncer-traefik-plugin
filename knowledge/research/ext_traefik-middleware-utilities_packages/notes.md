# traefik-middleware-utilities reclaim and simpleredis packages

## Layout

- Module: `github.com/david-garcia-garcia/traefik-middleware-utilities` (Go 1.21).
- Packages live at repo root as `reclaim/` and `simpleredis/`, not under `pkg/`.
- Latest tag: `v1.0.3` = `950b08de86b6fd9ea68ac1d205e17a379ec60522` (same pin as this finding’s clone).

## reclaim API (upstream v1.0.3)

- Caller owns a `*Table`: `reclaim.New(reclaim.Config{Grace: …})`. There is no process-wide `Default()`, `Open` package helper, `OpenWithGrace`, `Wrapped`, `Peek`, `PeekLivePrefix`, `View`, or `ResetForTest` / `ResetForTestWith`.
- Grace is freeze-at-New on the table (`Config.Grace`). Zero keeps nothing; negative becomes `DefaultGrace` (10s). There is no per-put grace override.
- `Table.Open(ctx, key, logger, create func() (any, error), hooks Hooks)` — lifecycle is explicit `Hooks{Sleep, Wake, Close, EnforceCloseBeforeOpen}`, stored at put. A later Open ignores the hooks argument.
- `Table.OpenWithHooks` lets `create` return `(any, Hooks, error)` so hooks can close over the just-built value.
- `OpenTyped[T]` is a function (not a method) for typed returns. Yaegi: instantiate only as a call expression; do not put a generic instantiation from another package on a package-level var or field.
- `Table.Reset()` is tests-only (not `ResetForTest`).
- Table internals (`items`, holder count, asleep vs awake) are unexported. A different package cannot implement Peek without a new upstream API.
- Upstream includes Yaegi-focused tests (`yaegi_test.go`, repro tests) not present in this plugin’s in-tree copy.

## simpleredis API (upstream v1.0.3)

- Construct with `simpleredis.New(Config{Host, Pass, Database, Logger, …}) (*SimpleRedis, error)`. There is no `Init` and no empty-struct-then-Init. New does not dial.
- Commands take `context.Context`: `Get(ctx, name)`, `MGet(ctx, names)`, `Set(ctx, name, data, duration)`, `Del(ctx, name)`, `Eval(ctx, script, digest, keys, args)`. This plugin’s stream lease uses `Eval` (`EVALSHA` then `EVAL` on NOSCRIPT). It does not use INCR or MSetEX.
- Same legacy error strings (`redis:unreachable`, `redis:miss`, …) plus exported sentinels `ErrUnreachable` / `ErrMiss` and helpers `IsMiss` / `IsUnreachable`.
- After `Close`, further commands return unreachable and do not dial (same contract as in-tree).
- Defaults differ from this plugin’s hardcoded timeouts (upstream dial 200ms / command 900ms vs in-tree dial 2s / I/O 1s). Zero Config uses those package defaults.

## Integration constraint for this product

- Plugin imports use `github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/reclaim` and `.../pkg/simpleredis` (`plugin_test.go`, `pkg/lapi/session.go`, `pkg/cache/cache.go`).
- Yaegi local/catalog load sees GOPATH + this module’s `vendor/` (`vendor/github.com/leprosus/golang-ttl-map`). A `go.mod` require of utilities must be vendored the same way. Do not patch `vendor/` of a module CI re-vendors.
- Live spec `openspec/specs/core_cache_redis_in-tree-client/spec.md` forbids importing published `github.com/maxlerebourg/simpleredis` and states `pkg/simpleredis` must not be required to match an outside simpleredis repo — tension with “replace with upstream utilities” unless spec and import paths are updated deliberately.
- Product reclaim imports utilities `reclaim` through the local shim (`Default`, `ProcessGrace`, `Open` / `OpenWithHooks`, test Reset). Peek / View are gone. Callers do not import utilities `reclaim` directly.

Sources: `.sources/traefik-middleware-utilities-repo.md`, `.sources/core_cache_redis_in-tree-client-spec.md`.
