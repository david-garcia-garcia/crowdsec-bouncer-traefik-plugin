## Why

Dest still pins `traefik-middleware-utilities` at v1.0.6 and keeps two local copies of APIs that tag `v1.0.7` (`42e6a1a967155318023c4defe491d1d423e165b6`) already publishes: `pkg/traefikemulator` and a hand-patched vendor reclaim tree. Depend on that tag and drop the copies.

## What Changes

- Require `github.com/david-garcia-garcia/traefik-middleware-utilities v1.0.7` in `go.mod` / `go.sum`. Re-vendor so `vendor/` matches the published module. Do not re-apply the dest reclaim `alias.go` / `table.go` diff.
- Delete `pkg/traefikemulator`. Point `zzz_traefikemulator_test.go` at `github.com/david-garcia-garcia/traefik-middleware-utilities/traefikemulator`. Swap the Test depguard allowlist. Point `docs/traefikemulator.md` at that import.
- Keep `pkg/reclaim` as the only product import of utilities reclaim. The shim compiles against published `SetAlias` / `Watch` / `ClearPublisher` / `Peek` / `Box` / `Published`.
- Update live specs that still name `v1.0.6` or “Peek is ad-hoc on vendored `table.go`”.
- Do not import utilities reclaim from `plugin.go` or other product packages. Do not copy local emulator package tests. Do not change simpleredis or iplookup.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `std_go_reclaim_context-lease`: Peek is the published utilities table method at the `go.mod` pin, still re-exported by the shim. Callers still import the shim, not utilities reclaim.
- `core_plugin_decisionstore_store`: Redis engine module pin `v1.0.6` → `v1.0.7`.
- `core_plugin_decisions_scopes`: Range Helper `Contains` / `Count` pin `v1.0.6` → `v1.0.7`.

Deleting `pkg/traefikemulator` is cleanup of an unspecified test helper. No spec folder.

## Impact

- `go.mod`, `go.sum`, `vendor/` (reclaim + new `traefikemulator`; simpleredis and iplookup blobs already match).
- `pkg/traefikemulator/` (delete), `zzz_traefikemulator_test.go` (import), `.golangci.yml` Test depguard, `docs/traefikemulator.md`.
- `pkg/reclaim/default.go` stays; it must compile against the published v1.0.7 API without a local `table.go`.
- Catalog deltas under the three Modified leaves. Usage: drop the “ad-hoc vendor override” sentence on `knowledge/devdocs/std_go_reclaim.md`.
