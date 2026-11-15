# Requirement
IssueKey: 2026-10-15-drop-gpl-test-dep

## Problem
This repository still carries GPL-3.0 test-only module `github.com/leprosus/golang-ttl-map` v1.1.7. The in-process memory backend no longer uses that map, so the remaining importer is a heap benchmark of a store the plugin does not ship.

Citation (delivery card, not a second product change): https://github.com/Optiways/crowdsec-bouncer-traefik-plugin/pull/1 (finding SUP-07, patch P-1).

## Current (code)
- `go.mod` requires `github.com/leprosus/golang-ttl-map v1.1.7`.
- `go.sum` has the two checksum lines for that module/version.
- `vendor/modules.txt` lists `# github.com/leprosus/golang-ttl-map v1.1.7` and package `github.com/leprosus/golang-ttl-map`.
- `vendor/github.com/leprosus/golang-ttl-map/` is the vendored copy (`map.go`, `License.md` GNU GPL v3, `Readme.md`, `.gitignore`).
- `.golangci.yml` Test depguard `allow` includes `github.com/leprosus/golang-ttl-map` (non-Test allow list does not).
- `pkg/decisionstore/zzz_lookup_bench_test.go` imports the module and defines `BenchmarkHeapRetained_TTLMap100k`; `BenchmarkHeapRetained_LiveMap100k` is in the same file.
- `pkg/decisionstore/memory.go` stores `map[string]LiveSlot` on tick/published snapshots; no `ttl_map` import.

## Desired
- Remove `BenchmarkHeapRetained_TTLMap100k` and its `ttl_map` import. Keep `BenchmarkHeapRetained_LiveMap100k`.
- Run `go mod tidy` and `go mod vendor` so the `go.mod` require, `go.sum` lines, vendored copy, and `vendor/modules.txt` entry are gone.
- Remove the depguard allow entry for `github.com/leprosus/golang-ttl-map`.

## Affected
- `pkg/decisionstore/zzz_lookup_bench_test.go`
- `go.mod`, `go.sum`
- `vendor/modules.txt`, `vendor/github.com/leprosus/golang-ttl-map/`
- `.golangci.yml`

## Out of scope
- Other patches on Optiways/crowdsec-bouncer-traefik-plugin#1; that URL is a citation of the same condition, not work to merge that fork.
- Changing `BenchmarkHeapRetained_LiveMap100k` or the live memory store.
- Squash-merge of this repository's pull request after GitHub CI on that PR has passed — process for a later phase, not a code change.

## Unknowns
- Exact leftover `go.sum` / vendor tree after tidy+vendor (implement measures).
- Whether Optiways PR #1 contains additional findings beyond SUP-07/P-1; they are not this change.

## Tensions
None. Ticket vs tree agree: only the TTLMap benchmark still imports the module; `pkg/decisionstore/memory.go` does not.
