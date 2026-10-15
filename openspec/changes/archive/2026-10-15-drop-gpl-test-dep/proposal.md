## Why

This repository still requires GPL-3.0 test-only module `github.com/leprosus/golang-ttl-map` v1.1.7. The in-process memory backend no longer uses that map; the only remaining importer is `BenchmarkHeapRetained_TTLMap100k`, a heap bench of a store the plugin does not ship. Citation of the same condition (not a second product change): https://github.com/Optiways/crowdsec-bouncer-traefik-plugin/pull/1 (SUP-07 / P-1).

## What Changes

- Delete `BenchmarkHeapRetained_TTLMap100k` and its `ttl_map` import from `pkg/decisionstore/zzz_lookup_bench_test.go`. Keep `BenchmarkHeapRetained_LiveMap100k` and `pkg/decisionstore/memory.go` as they are.
- Run `go mod tidy` and `go mod vendor` so the `go.mod` require, `go.sum` lines, vendored copy, and `vendor/modules.txt` entry for `github.com/leprosus/golang-ttl-map` are gone.
- Remove the Test depguard `allow` entry for `github.com/leprosus/golang-ttl-map` from `.golangci.yml`.

## Capabilities

### New Capabilities

None. Absence-only cleanup of an unused test module. No live promise.

### Modified Capabilities

None. Live `core_plugin_decisionstore_store` already requires that memory MUST NOT Set stream or live Ip or header keys on a TTL heap. This change does not modify that SHALL. Change `.openspec.yaml` sets `skip_specs: true`.

## Impact

- `pkg/decisionstore/zzz_lookup_bench_test.go` (delete TTLMap bench + import only).
- `go.mod`, `go.sum`.
- `vendor/modules.txt`, `vendor/github.com/leprosus/golang-ttl-map/` (entire vendored copy).
- `.golangci.yml` Test depguard allow list.
- Out of scope: other patches on Optiways/crowdsec-bouncer-traefik-plugin#1; changing `BenchmarkHeapRetained_LiveMap100k` or the live memory store; rewriting historical research, debt, or archive text that still names golang-ttl-map.
