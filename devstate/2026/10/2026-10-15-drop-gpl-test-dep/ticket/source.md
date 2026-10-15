# 2026-10-15-drop-gpl-test-dep

Drop the GPL-3.0 test-only dependency github.com/leprosus/golang-ttl-map v1.1.7 from this repository. The same condition is described by Optiways pull request https://github.com/Optiways/crowdsec-bouncer-traefik-plugin/pull/1 (finding SUP-07, patch P-1): go.mod requires the module, vendor/modules.txt vendors it, .golangci.yml depguard allows it, and the only Go importer is BenchmarkHeapRetained_TTLMap100k in pkg/decisionstore/zzz_lookup_bench_test.go. The memory backend no longer uses ttl_map, so that benchmark measures a store the plugin does not ship. Remove that benchmark and its import. Keep BenchmarkHeapRetained_LiveMap100k. Run go mod tidy and go mod vendor so the require, the go.sum lines, the vendored copy, and the modules.txt entry are gone. Remove the depguard allow entry.

The delivery card for this run must mention https://github.com/Optiways/crowdsec-bouncer-traefik-plugin/pull/1.

After this repository's pull request is open and GitHub CI on that pull request has passed, squash-merge it.
