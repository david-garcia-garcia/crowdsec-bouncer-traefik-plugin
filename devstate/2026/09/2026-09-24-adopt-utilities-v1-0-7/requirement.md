# Requirement
IssueKey: 2026-09-24-adopt-utilities-v1-0-7

## Problem
Dest still requires traefik-middleware-utilities v1.0.6 and keeps two copies of APIs that v1.0.7 now publishes: a local `pkg/traefikemulator` and a hand-patched vendor reclaim tree (`alias.go` plus table edits). The ask is to depend on v1.0.7 (tag `v1.0.7`, commit `42e6a1a967155318023c4defe491d1d423e165b6`) and drop those local copies.

## Current (code)
- `go.mod` requires `github.com/david-garcia-garcia/traefik-middleware-utilities v1.0.6`.
- `go.sum` pins the v1.0.6 hashes.
- `vendor/modules.txt` lists that module at v1.0.6 (`iplookup`, `reclaim`, `simpleredis` only; no `traefikemulator`).
- `pkg/traefikemulator/emulator.go` is the in-repo emulator (New/Apply/Serve).
- `zzz_traefikemulator_test.go` imports `github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/traefikemulator`.
- `vendor/github.com/david-garcia-garcia/traefik-middleware-utilities/reclaim/alias.go` is an ad-hoc vendor override (SetAlias/Watch/Published/Box).
- `vendor/github.com/david-garcia-garcia/traefik-middleware-utilities/reclaim/table.go` is the vendored table that those alias edits sit on.
- `pkg/reclaim/default.go` is the plugin shim: type aliases and `SetAlias`/`Watch`/`Peek`/`ClearPublisher` forward to the utilities module.

## Desired
- `go.mod` / `go.sum` require v1.0.7. Re-vendor so `vendor/` matches that module. Do not keep a hand-patched vendor tree for packages v1.0.7 already publishes.
- Delete `pkg/traefikemulator`. Callers (including `zzz_traefikemulator_test.go` and any other import of `github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pkg/traefikemulator`) import `github.com/david-garcia-garcia/traefik-middleware-utilities/traefikemulator` instead.
- Plugin reclaim code keeps using the module and must compile against the v1.0.7 API. Do not re-apply the old vendor diff.
- Tests that used the local emulator keep passing against the upstream package.

## Affected
- `go.mod`, `go.sum`, `vendor/`
- `pkg/traefikemulator/` (delete)
- `zzz_traefikemulator_test.go` (import)
- `pkg/reclaim/default.go` (must compile against v1.0.7)

## Out of scope
- Tagging or releasing the bouncer itself.
- Changing upstream further.
- Unrelated simpleredis work unless re-vendoring v1.0.7 removes a local patch the plugin still needs (record that as an unknown; do not invent a feature).

## Unknowns
- Whether the published v1.0.7 `traefikemulator` API matches `pkg/traefikemulator` enough for existing tests with only an import change.
- Whether the published v1.0.7 reclaim alias API matches the current vendor override and the `pkg/reclaim` shim.
- Whether dest `vendor/.../simpleredis` contains a local patch that a clean v1.0.7 re-vendor would drop.
- Whether any other file besides `zzz_traefikemulator_test.go` imports `pkg/traefikemulator` after dest HEAD (only that test import was found on this tree).

## Tensions
- None. Ticket, dest code, and the named local copies agree.
