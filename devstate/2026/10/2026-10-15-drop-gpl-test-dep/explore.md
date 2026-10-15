# Explore

## Concepts

The leftover is a test-only Go module, not a runtime DecisionStore backend.

- **Module graph** — `go.mod` (`require github.com/leprosus/golang-ttl-map v1.1.7`), two `go.sum` lines, `vendor/modules.txt` (`# github.com/leprosus/golang-ttl-map v1.1.7` plus package `github.com/leprosus/golang-ttl-map`). Job: keep the module buildable for tests.
- **Vendored copy** — `vendor/github.com/leprosus/golang-ttl-map/` (`.gitignore`, `License.md`, `map.go`, `Readme.md`). Job: ship the module for Yaegi/`go test` vendor mode.
- **Test depguard allow** — `.golangci.yml` `depguard.rules.Test.allow` lists `github.com/leprosus/golang-ttl-map`. `Main` (`$all` minus `$test`) does not.
- **Heap benchmark** — `pkg/decisionstore/zzz_lookup_bench_test.go` `BenchmarkHeapRetained_TTLMap100k` plus `ttl_map "github.com/leprosus/golang-ttl-map"`. Job: compare retained heap of a store the plugin does not ship.
- **Live memory store** — `pkg/decisionstore/memory.go` (`map[string]LiveSlot` tick/published). Job: in-process DecisionStore engine. No `ttl_map` import.
- **Live heap benchmark** — same bench file, `BenchmarkHeapRetained_LiveMap100k`. Job: measure the shipped map. Out of scope to change.

```
go.mod require ──► vendor/ + modules.txt ──► Test-only import
                                              │
.golangci.yml Test allow ─────────────────────┤
                                              ▼
                         zzz_lookup_bench_test.go
                           BenchmarkHeapRetained_TTLMap100k
                         memory.go (no import; LiveSlot maps)
                           BenchmarkHeapRetained_LiveMap100k (keep)
```

Call sites of the module import (existing callers to migrate by deletion): **1** Go importer.

- Roots searched: worktree `**/*.go` (including `pkg/`, excluding only the vendored `map.go` itself), `go.mod`, `go.sum`, `vendor/modules.txt`, `.golangci.yml`.
- `go list -f TestImports ./pkg/decisionstore/` includes `github.com/leprosus/golang-ttl-map`. Production `Imports` does not.
- `go mod why github.com/leprosus/golang-ttl-map` is only `pkg/decisionstore` → `pkg/decisionstore.test` → the module.

Reproduce: **reproduced** on worktree `d:\repositories\crowdsec-bouncer-traefik-plugin-2026-10-15-drop-gpl-test-dep`.

| Claim | Path run | Result |
| --- | --- | --- |
| `go.mod` require v1.1.7 | `go.mod:5` | present |
| Two `go.sum` lines | `go.sum:3-4` | present |
| `vendor/modules.txt` entry | `vendor/modules.txt` | present |
| Vendored GPL-3.0 | `vendor/github.com/leprosus/golang-ttl-map/License.md` line 1–2 `GNU GENERAL PUBLIC LICENSE` / `Version 3, 29 June 2007` | present; files `.gitignore`, `License.md`, `map.go`, `Readme.md` |
| Sole test importer | `go list` TestImports + `go mod why` + `*.go` search | only `zzz_lookup_bench_test.go` |
| Test depguard allow, not Main | `.golangci.yml` Test allow; Main allow has no `leprosus` | present |
| memory.go unused | `pkg/decisionstore/memory.go` imports | no `ttl_map` |

Did not run `go test` or the heap benchmarks (explore does not implement). Did not fetch Optiways PR #1 as a code change.

Outside facts: in-tree `License.md` (GPL-3.0). No new `knowledge/research/` write. Existing notes that mention the vendor path (`knowledge/research/ext_redis_commands_set-ex-zero/`, `knowledge/research/ext_traefik-middleware-utilities_packages/`) are historical; they are not this ticket. Citation (delivery card, not a second product change): https://github.com/Optiways/crowdsec-bouncer-traefik-plugin/pull/1 (SUP-07 / P-1).

Usage consumed: `knowledge/devdocs/index.md` (no `priority: always`), `index_core_plugin.md` → `core_plugin_decisionstore.md` (Language already `_Avoid_`s process `ttl_map`; usage already names `map[string]LiveSlot`), `index_std_go.md` → `std_go_test_zzz-prefix.md` (keep the `zzz_` bench file), `index_build_ci.md` → `build_ci_github.md` (no depguard packet). Language/usage enough — produce nothing.

Identity: this change does not set or reconstruct client address, user, tenant, Host, or trust hop.

## Decisions

- **Chosen:** Delete `BenchmarkHeapRetained_TTLMap100k` and its `ttl_map` import; keep `BenchmarkHeapRetained_LiveMap100k` and `memory.go`; run `go mod tidy` and `go mod vendor`; remove the Test depguard allow for `github.com/leprosus/golang-ttl-map`.
- **Rejected:** Rewrite the TTLMap bench onto `map[string]LiveSlot` — would keep a second heap bench the requirement does not ask for and would change the LiveMap neighbor's comparison story.
- **Rejected:** Keep the module as an unused require — leaves GPL-3.0 in `go.mod` / vendor after the importer is gone.
- **Rejected:** Merge or cherry-pick Optiways/crowdsec-bouncer-traefik-plugin#1 — that URL is a citation of the same condition, not work to merge that fork.
- **Live contract:** `no live contract`. Cleanup of an unused test module. Live `openspec/specs/core_plugin_decisionstore_store/spec.md` already says memory MUST NOT Set stream or live keys on a TTL heap; this change does not modify that promise.

## Open questions

- Q: How should the leftover golang-ttl-map module be removed?
  Rank: bounded asked — 1 existing Go importer plus module-graph and Test depguard allow enumerated (roots: pkg, go.mod, go.sum, vendor/modules.txt, .golangci.yml); Desired first two bullets name this reshape
  Decision: resolved — remove BenchmarkHeapRetained_TTLMap100k and the ttl_map import from pkg/decisionstore/zzz_lookup_bench_test.go; keep BenchmarkHeapRetained_LiveMap100k; go mod tidy + go mod vendor; delete the Test depguard allow entry.
  By: explore

- Q: What exact leftover go.sum / vendor tree remains after tidy+vendor?
  Rank: additive asked — Desired bullet names go mod tidy and go mod vendor so the go.mod require, go.sum lines, vendored copy, and vendor/modules.txt entry are gone
  Decision: resolved — after tidy+vendor the go.mod require, two go.sum lines, vendor/modules.txt entry, and vendor/github.com/leprosus/golang-ttl-map/ are gone. No extra leftovers.
  By: implement

- Q: Does Optiways PR 1 contain additional findings beyond SUP-07/P-1?
  Rank: additive asked — Out of scope: Other patches on Optiways/crowdsec-bouncer-traefik-plugin#1; that URL is a citation of the same condition, not work to merge that fork.
  Decision: assumed — citation only on the delivery card (https://github.com/Optiways/crowdsec-bouncer-traefik-plugin/pull/1); do not ingest or merge other findings from that URL.
  By: explore

- Q: Does dropping the unused test module need a live catalog spec delta?
  Rank: additive asked — unused test module, never a remaining production promise (Live catalog: unused code/files, never specified)
  Decision: resolved — none — no live contract. Propose journals that. Do not ADDED the module is absent.
  By: explore

- Q: Should this change rewrite research, debt, or archive text that still names golang-ttl-map?
  Rank: additive incidental — no existing caller contract reshaped; no criterion names research rewrite
  Decision: assumed — leave knowledge/research/ext_redis_commands_set-ex-zero/, knowledge/research/ext_traefik-middleware-utilities_packages/, knowledge/debt/2026-09-19-multiple-decisions-per-cache-key.md, and openspec/changes/archive untouched. Historical mentions stay.
  By: explore

- Q: Must BenchmarkHeapRetained_LiveMap100k or pkg/decisionstore/memory.go change?
  Rank: additive asked — Out of scope: Changing BenchmarkHeapRetained_LiveMap100k or the live memory store.
  Decision: resolved — keep both as they are.
  By: explore