## Context

See proposal.md Why. Dest `go.mod` requires `traefik-middleware-utilities v1.0.6`. `vendor/modules.txt` lists `iplookup`, `reclaim`, `simpleredis` only. `pkg/traefikemulator` is an in-repo generation helper; one other-package import (`zzz_traefikemulator_test.go`). Dest vendor reclaim is v1.0.6 plus a local `alias.go` and table edits. `pkg/reclaim` is the only product importer of utilities reclaim.

Research at `knowledge/research/ext_traefik-middleware-utilities_traefikemulator/` and `…_reclaim_alias/`: tag `v1.0.7` is `42e6a1a967155318023c4defe491d1d423e165b6`. Published `emulator.go` is the same blob as `pkg/traefikemulator/emulator.go`. Published `SetAlias` / `Watch` / `ClearPublisher` / `Peek` / `Box` / `Published` match the shim. Dest `simpleredis` and `iplookup` blobs already equal that tag.

FindSpecHost (propose, before folder write):

```
verdicts:
  - { deltaId: peek-published-owner, fold|new|skip: fold, spec-id: std_go_reclaim_context-lease, confidence: high, candidates: [std_go_reclaim_context-lease, core_plugin_middleware_instance-slots] }
  - { deltaId: decisionstore-module-pin, fold|new|skip: fold, spec-id: core_plugin_decisionstore_store, confidence: high, candidates: [core_plugin_decisionstore_store] }
  - { deltaId: decisions-scopes-module-pin, fold|new|skip: fold, spec-id: core_plugin_decisions_scopes, confidence: high, candidates: [core_plugin_decisions_scopes, core_plugin_ip_radix-lookup] }
  - { deltaId: delete-local-emulator, fold|new|skip: skip, spec-id: none, confidence: high, candidates: [] }
```

Small pin / Peek-owner adjustments. Emulator delete is cleanup of unspecified code. `core_plugin_middleware_instance-slots` does not name v1.0.6 or ad-hoc Peek — no delta.

## Goals / Non-Goals

**Goals:**

- One module pin: v1.0.7. Vendor tree matches the published module.
- One emulator owner: the published package. Local `pkg/traefikemulator` gone.
- Shim stays the only product import of utilities reclaim and compiles without a local `table.go`.
- Catalog pin and Peek-owner sentences match the published module.

**Non-Goals:**

- New catalog leaf for the emulator helper.
- Importing utilities reclaim from `plugin.go` or other product packages.
- Copying `pkg/traefikemulator/zzz_emulator_test.go` into this repo.
- Changing simpleredis or iplookup sources.
- Tagging this plugin or changing upstream.

## Decisions

| Topic | Choice | Rationale |
|-------|--------|-----------|
| Vendor | `go get` v1.0.7 then `go mod vendor`. Take published reclaim and traefikemulator. | Desired forbids re-applying the dest reclaim diff. Published files own Peek and alias. |
| Emulator caller | Import change on `zzz_traefikemulator_test.go` only. Delete the local package and its same-package tests. | Same blob; upstream `emulator_test.go` is a superset. |
| Lint | Replace Test depguard `…/pkg/traefikemulator` with `…/traefik-middleware-utilities/traefikemulator`. | Tests import the published package. Main allowlist already omits the local helper. |
| Docs | Point `docs/traefikemulator.md` at the published import. | The local path dies with the package. |
| Shim | Keep `pkg/reclaim`. Do not retarget product callers. | Live spec and 21 importers. One job, one owner. |
| Catalog | Fold the three Modified leaves. Skip emulator cleanup. | Live catalog: pin and Peek owner are remaining promises. Absence of `pkg/traefikemulator` is not. |
| Usage | Drop the “ad-hoc vendor override” sentence on `std_go_reclaim.md`. | That sentence is false at v1.0.7. Instance-slots usage stays. |

**Alternatives rejected:** keep the local emulator and only bump reclaim; re-apply dest `alias.go` / table edits after vendor; delete the shim and import utilities reclaim at every call site; invent a new emulator spec leaf.

## Risks / Trade-offs

- **Vendor table.go blob differs from dest** → Accepted. Published v1.0.7 adds `//nolint:exhaustive` on Peek; dest comment still said “Ad-hoc vendor override”. Take the published files.
- **Test depguard misses the new import** → Swap the Test allowlist in the same edit as the import.
- **A later dest HEAD adds another `pkg/traefikemulator` import** → Explore found one. Implement re-searches `*.go` before delete.

## Migration Plan

- Deploy with the bumped module. No config rewrite. Rollback is revert of the PR.

## Open Questions

None. Explore rows stay as explore/propose wrote them.
