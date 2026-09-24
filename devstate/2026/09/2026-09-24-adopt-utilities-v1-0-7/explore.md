# Explore

## Concepts

Units this change would touch:

| Unit | Path | Job |
|------|------|-----|
| Utilities pin | `go.mod`, `go.sum`, `vendor/modules.txt` | Dest requires `traefik-middleware-utilities v1.0.6`. Re-vendor v1.0.7 so `vendor/` matches the published module. |
| Local emulator | `pkg/traefikemulator/` | In-repo generation helper (`New`/`Apply`/`Stop`/`Handler`/`Serve`). Delete after callers import the published package. |
| Plugin emulator tests | `zzz_traefikemulator_test.go` | Only other-package Go import of `pkg/traefikemulator`. Exercises plugin `New` through the helper. |
| Emulator package tests | `pkg/traefikemulator/zzz_emulator_test.go` | Same-package tests of the helper. Deleted with the package; upstream `emulator_test.go` is a superset. |
| Lint allowlist | `.golangci.yml` Test depguard | Allows `.../pkg/traefikemulator`. Must allow `.../traefik-middleware-utilities/traefikemulator` after the import change. |
| Emulator doc | `docs/traefikemulator.md` | Points at `pkg/traefikemulator`. Update the import path when the package is deleted. |
| Reclaim shim | `pkg/reclaim/default.go` | Only importer of utilities `reclaim`. Type aliases + `Default`/`OpenWithHooks`/`Peek`/`SetAlias`/`Watch`/`ClearPublisher`/`ResetForTest*`. Keep. |
| Dest vendor reclaim | `vendor/.../reclaim/alias.go`, `table.go` | Ad-hoc override (alias + Peek + unbind). Replace with published v1.0.7 files. Do not re-apply the dest diff. |
| Live pin specs | `openspec/specs/std_go_reclaim_context-lease`, `core_plugin_decisionstore_store`, `core_plugin_decisions_scopes` | Still name v1.0.6 and/or “ad-hoc Peek on vendored table.go”. Propose updates the pin and Peek owner sentence. |

```
  Traefik New (plugin.go)
        │
        ├─ reclaim.OpenWithHooks ──► pkg/reclaim shim ──► utilities/reclaim Table
        ├─ reclaim.SetAlias / ClearPublisher / Watch
        └─ bouncer atomic.Value ◄── Watch Published

  Test generation
        zzz_traefikemulator_test.go
              │
              └─ traefikemulator.New(plugin.New) → Apply → Serve
```

Call sites (roots: worktree `*.go`, `*.md`, `*.yml`, `*.yaml`; patterns `pkg/traefikemulator`, `traefik-middleware-utilities/traefikemulator`, `traefik-middleware-utilities/reclaim`):

- `pkg/traefikemulator` Go imports: **1** (`zzz_traefikemulator_test.go`). Same-package tests: **1** file. Mentions: `docs/traefikemulator.md`, `.golangci.yml` Test allowlist. Production code does not import it.
- utilities `reclaim` imports: **1** (`pkg/reclaim/default.go`).
- `pkg/reclaim` shim imports: **21** other-package files (6 production: `plugin.go`, `pkg/lapi/session.go`, `pkg/appsec/session.go`, `pkg/captcha/session.go`, `pkg/decisionstore/store.go`, `pkg/bouncer/bouncer.go`; 15 tests). They stay on the shim.

Reproduce: dest `go.mod` requires `v1.0.6`; `vendor/modules.txt` lists `iplookup`, `reclaim`, `simpleredis` only. Not a failing test.

Outside facts: `knowledge/research/ext_traefik-middleware-utilities_traefikemulator/`, `knowledge/research/ext_traefik-middleware-utilities_reclaim_alias/`. Tag `v1.0.7` = `42e6a1a967155318023c4defe491d1d423e165b6` (GitHub ref).

This change does not set or reconstruct client address, user, tenant, Host, or trust hop. `pkg/ip.GetRemoteIP` stays the owner.

## Decisions

- Bump the module to v1.0.7 and `go mod vendor`. Take the published `reclaim/` and `traefikemulator/` trees. Do not keep a hand-patched vendor reclaim.
- Delete `pkg/traefikemulator`. Point `zzz_traefikemulator_test.go` at `github.com/david-garcia-garcia/traefik-middleware-utilities/traefikemulator`. Swap the Test depguard allowlist. Point `docs/traefikemulator.md` at the published import.
- Keep `pkg/reclaim` as the only product import of utilities reclaim. Shim compiles against published `SetAlias`/`Watch`/`ClearPublisher`/`Peek`/`Box`/`Published` without a local `table.go`.
- Propose updates live specs that still say `v1.0.6` or “Peek is ad-hoc on vendored table.go”. Keep the shim-only import rule and instance-slot alias behavior.
- Do not import utilities reclaim from `plugin.go` or other product packages. Do not copy `zzz_emulator_test.go` elsewhere. Do not change simpleredis or iplookup (dest blobs already match v1.0.6 and v1.0.7).

Rejected:

- Keep `pkg/traefikemulator` and only bump reclaim — Desired deletes the local package.
- Re-apply dest `alias.go` / table edits after vendor — Desired forbids it; v1.0.7 already publishes them.
- Delete the shim and import utilities reclaim at every call site — live spec and usage say callers import the shim; 21 files would move for no product job.

Live contract: `std_go_reclaim_context-lease` (shim + Peek owner), `core_plugin_middleware_instance-slots` (SetAlias/Watch/ClearPublisher), `core_plugin_decisionstore_store` and `core_plugin_decisions_scopes` (module pin `v1.0.6`). No live spec for the emulator helper itself.

## Open questions

- Q: Does published v1.0.7 `traefikemulator` match `pkg/traefikemulator` enough for an import-only change on existing tests?
  Rank: bounded asked — 1 Go import plus same-package tests enumerated; Desired “Delete `pkg/traefikemulator`” and “import `.../traefikemulator` instead”
  Decision: resolved — `emulator.go` at `42e6a1a` is git-blob `3e023e09…`, the same file as `pkg/traefikemulator/emulator.go`. `zzz_traefikemulator_test.go` needs only the import (and the lint allowlist). Delete the local package tests; upstream `emulator_test.go` already covers them.
  By: explore

- Q: Does published v1.0.7 reclaim alias API match the dest vendor override and the `pkg/reclaim` shim?
  Rank: bounded asked — 1 utilities/reclaim importer enumerated; Desired “compile against the v1.0.7 API” and “Do not re-apply the old vendor diff”
  Decision: resolved — published `SetAlias`/`Watch`/`ClearPublisher`/`Box`/`Published`/`Peek`/`State` match what the shim forwards. Keep the shim. Re-vendor the published `alias.go` and `table.go`.
  By: explore

- Q: Does dest `vendor/.../simpleredis` contain a local patch that a clean v1.0.7 re-vendor would drop?
  Rank: bounded asked — Out of scope “record that as an unknown”; hashed dest `simpleredis` and `iplookup` production files
  Decision: resolved — dest `simpleredis` and `iplookup` blobs equal published v1.0.6 and v1.0.7. Re-vendor does not drop a dest patch there. Do not invent simpleredis work.
  By: explore

- Q: Does any file besides `zzz_traefikemulator_test.go` import `pkg/traefikemulator` after dest HEAD?
  Rank: bounded asked — Unknowns line; searched `*.go`/`*.md`/`*.yml`/`*.yaml`
  Decision: resolved — one other-package import (`zzz_traefikemulator_test.go`). Same-package tests live under `pkg/traefikemulator/`. Mentions: `docs/traefikemulator.md`, `.golangci.yml` Test allowlist. No production import.
  By: explore

- Q: How should live specs that still name v1.0.6 or ad-hoc vendored Peek be updated?
  Rank: bounded asked — 3 catalog files enumerated; Desired go.mod / go.sum require v1.0.7
  Decision: assumed — propose MODIFIED pin v1.0.6 to v1.0.7 on core_plugin_decisionstore_store and core_plugin_decisions_scopes; on std_go_reclaim_context-lease say Peek is the published table method at the pin, still re-exported by the shim. Keep callers import the shim.
  By: explore
