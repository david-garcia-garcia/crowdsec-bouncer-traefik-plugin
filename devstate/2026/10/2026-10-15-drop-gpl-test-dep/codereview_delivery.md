# Delivery

## Motivation

The in-process memory DecisionStore already keeps live keys on `map[string]LiveSlot`. The module graph still required `github.com/leprosus/golang-ttl-map` v1.1.7, a GPL-3.0 package, even though production imports of that store do not use it.

The only remaining importer was `BenchmarkHeapRetained_TTLMap100k`, a retained-heap bench of a store the plugin does not ship. Test depguard allowed that import; Main did not. The vendored copy still carried the GPL-3.0 license with the module.

Left alone, the tree keeps an unused GPL-3.0 test dependency in the module graph and vendor with no runtime effect: a license and internal-clarity gap, not a serving or operator failure. The same leftover was noted as SUP-07 / P-1 at https://github.com/Optiways/crowdsec-bouncer-traefik-plugin/pull/1; that URL is a citation of this condition, not a second product change.

Priority: P3 — unused GPL-3.0 test module, no current user or operator harm

## Implementation

The TTLMap bench and its `ttl_map` import were deleted so nothing in the tree still referenced the module. `go mod tidy` and `go mod vendor` then dropped the `go.mod` require, the two `go.sum` lines, the `vendor/modules.txt` entry, and the vendored copy. The Test depguard allow for `github.com/leprosus/golang-ttl-map` was removed so a later re-import fails lint.

`BenchmarkHeapRetained_LiveMap100k` and the live memory store were left as they are. Live `core_plugin_decisionstore_store` already forbids TTL-heap Sets; there is no spec delta. https://github.com/Optiways/crowdsec-bouncer-traefik-plugin/pull/1 was not merged or cherry-picked; it remains a citation of the same leftover, not work folded in from that fork.

## What this changes
**Operators.** None.
**Admin users.** None.
**Developers.** Test and production code must not import `github.com/leprosus/golang-ttl-map`; Test depguard no longer allows it, and the unused GPL-3.0 module is gone from the graph and vendor.
**End users.** None.
