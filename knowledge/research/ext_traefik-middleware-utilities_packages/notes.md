# traefik-middleware-utilities reclaim and simpleredis packages

## Layout

- Module: `github.com/david-garcia-garcia/traefik-middleware-utilities` (Go 1.21).
- Packages live at repo root as `reclaim/` and `simpleredis/`, not under `pkg/`.
- Pinned clone: `david-garcia-garcia/traefik-middleware-utilities@950b08de86b6fd9ea68ac1d205e17a379ec60522`.

## reclaim API (upstream)

- `Table.Open(ctx, key, logger, create func() (any, error), hooks Hooks)` — lifecycle hooks are explicit `Hooks`, not optional `Sleep`/`Wake`/`Close` methods on the stored value alone.
- `Table.OpenWithHooks` and generic `OpenTyped[T]` for typed returns under Yaegi constraints (see upstream `reclaim/opentyped.go` comments).
- Upstream includes Yaegi-focused tests (`yaegi_test.go`, repro tests) not present in the plugin’s in-tree copy.

## simpleredis API (upstream)

- Stdlib pooled TCP RESP client; exports `errors.Is`-friendly sentinels (`ErrMiss`, `ErrUnreachable`, etc.) in addition to legacy string constants.
- Broader command surface (pool, `MSetEX`, `EVAL`, config, fuzz/injection tests) than the plugin’s three-file `pkg/simpleredis`.

## Integration constraint for this product

- Plugin imports use `github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/reclaim` and `.../pkg/simpleredis` (`plugin_test.go`, `pkg/lapi/session.go`, `pkg/cache/cache.go`).
- Live spec `openspec/specs/core_cache_redis_in-tree-client/spec.md` forbids importing published `github.com/maxlerebourg/simpleredis` and states `pkg/simpleredis` must not be required to match an outside simpleredis repo — tension with “replace with upstream utilities” unless spec and import paths are updated deliberately.

Sources: `.sources/traefik-middleware-utilities-repo.md`, `.sources/core_cache_redis_in-tree-client-spec.md`.
