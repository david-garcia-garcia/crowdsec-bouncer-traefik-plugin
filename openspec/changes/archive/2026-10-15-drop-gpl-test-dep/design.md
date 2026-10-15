## Context

See proposal.md — Why. One Go importer remains: `pkg/decisionstore/zzz_lookup_bench_test.go` (`BenchmarkHeapRetained_TTLMap100k` plus `ttl_map "github.com/leprosus/golang-ttl-map"`). Production `Imports` of `pkg/decisionstore` do not include the module. `go.mod` requires v1.1.7; `go.sum` has two checksum lines; `vendor/modules.txt` lists the module and package; `vendor/github.com/leprosus/golang-ttl-map/` is the vendored copy (`map.go`, GPL-3.0 `License.md`, `Readme.md`, `.gitignore`). `.golangci.yml` Test depguard `allow` lists the module; Main does not. `pkg/decisionstore/memory.go` stores `map[string]LiveSlot` and has no `ttl_map` import. Live `core_plugin_decisionstore_store` already forbids TTL-heap Sets; no spec delta.

## Goals / Non-Goals

**Goals:**
- Drop the sole importer first, then let `go mod tidy` and `go mod vendor` drop the module graph and vendor tree.
- Drop the Test depguard allow so lint matches the gone import.
- Keep the `zzz_lookup_bench_test.go` file (other benches stay).

**Non-Goals:**
- Do not change `BenchmarkHeapRetained_LiveMap100k` or `memory.go`.
- Do not invent extra leftovers after tidy+vendor.
- Do not merge or cherry-pick Optiways/crowdsec-bouncer-traefik-plugin#1.
- Do not rewrite historical research, debt, or archive text that still names golang-ttl-map.
- Do not write `openspec/changes/drop-gpl-test-dep/specs/`.

## Decisions

- **Delete the TTLMap bench and its import.** Alternative: rewrite that bench onto `map[string]LiveSlot` — rejected; would keep a second heap bench the requirement does not ask for and would change the LiveMap neighbor's comparison story.
- **Tidy then vendor after the importer is gone.** Alternative: keep an unused `require` — rejected; leaves GPL-3.0 in `go.mod` / vendor.
- **Remove the Test depguard allow in the same change.** Alternative: leave the allow — rejected; it would be a dead exception after the import is gone.
- **Citation only for Optiways PR #1.** Alternative: ingest or merge other findings from that URL — rejected; Out of scope. Delivery card cites https://github.com/Optiways/crowdsec-bouncer-traefik-plugin/pull/1 (SUP-07 / P-1).
- **No live catalog delta.** Alternative: ADDED "the module is absent" — rejected; unused test module, never a remaining production promise.

## Risks / Trade-offs

- [Risk] `go mod tidy` / `go mod vendor` leave extra checksum or vendor noise. → Mitigation: implement measures after those commands; expect the require, two `go.sum` lines, vendored directory, and `vendor/modules.txt` entry gone; do not invent extra leftovers.
- [Risk] A later edit re-imports the module. → Mitigation: the Test depguard allow is removed so lint fails on that import.

## Migration Plan

Delete the bench and import, tidy, vendor, drop the allow. Rollback is revert the change; no persistent store or operator config moves.
