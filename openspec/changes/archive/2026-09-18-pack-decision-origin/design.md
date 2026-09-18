## Context

See `proposal.md` Why. Dest `master` concatenates `RemediationWithOrigin` (letter + U+001F + origin) into ttl_map and copies the origin again into `MetricsReporter.activeDecisionSlots` as a five-string `usageMetricKey` (`pkg/cache/remediation.go`, `pkg/lapi/client_metrics.go`, `pkg/lapi/client_decisions.go`, `pkg/lapi/client_stream.go`). `cacheInterface` get/set is `string`; `localCache` type-asserts ttl_map `interface{}` to string. `DecisionStore` is the cache reclaim value; `MetricsReporter` is a pointer on `Client`, not its own reclaim object. Live/none SessionHex includes mode so they do not share this store. Explore reproduced ~108–115 MiB HeapAlloc at 400K IPv4; packed + compact slots ~54 MiB.

FindSpecHost:

```
verdicts:
  - { deltaId: origin-dictionary-and-packed-memory, fold|new: new, spec-id: core_cache_client_origin-dictionary, confidence: high, candidates: [core_cache_client_decision-store, core_cache_client_isolated-store, core_plugin_lapi_usage-metrics, core_plugin_lapi_reclaim-key] }
  - { deltaId: memory-payloads-not-only-strings, fold|new: fold, spec-id: core_cache_client_decision-store, confidence: high, candidates: [core_cache_client_decision-store] }
  - { deltaId: lookup-kind-without-origin-on-allow, fold|new: fold, spec-id: core_plugin_decisions_scopes, confidence: high, candidates: [core_plugin_decisions_scopes, core_plugin_lapi_stream-apply] }
  - { deltaId: compact-active-decision-slots, fold|new: fold, spec-id: core_plugin_lapi_usage-metrics, confidence: high, candidates: [core_plugin_lapi_usage-metrics] }
```

Search: families `core_cache_client`, `core_plugin_lapi`, `core_plugin_decisions`. Existing leaves `decision-store` (reclaim + "opaque strings"), `isolated-store` (key space), `usage-metrics` (POST labels + slot map), `stream-apply` (deleted-before-new), `decisions_scopes` (letter + U+001F suffix, lookup). No in-flight change folder. Archived related: `shared-decision-store`, `extract-metrics-reporter`, `origin-for-range-decisions`.

Origin dictionary + packed memory word is a large new capability (intern table, overflow, lock-free reads, dual backend) → **new** `core_cache_client_origin-dictionary` under family `core_cache_client` (table lives on DecisionStore; packed ids are cache payload). Do not use the change kebab as the 4th part. Opaque-strings SHALL must be amended → **fold** `decision-store` (one–three requirements). Lookup/Range matching of packed vs suffix → **fold** `decisions_scopes` (small adjustment to "Remediation cache values may carry origin" plus resolve-on-drop). Compact slots without changing POST labels → **fold** `usage-metrics`. Do not fold packing into `stream-apply` (order only). `decision-store` / `usage-metrics` name their units; not vague.

## Goals / Non-Goals

**Goals:**

- One DecisionStore table; packed memory values; compact slots; Redis and live/none stay on the string codec.
- Kind on the allow path without intern `mu` and without formatting a U+001F string.
- Same `active_decisions` / `dropped` labels as dest.

**Non-Goals:**

- Redis intern table or smaller Redis payloads.
- Replacing ttl_map or introducing custom IP-as-bytes maps.
- Dropping `activeDecisionSlots`.
- Public config.
- AppSec, captcha, live/none LAPI query shape.
- Usage Language writes in this change folder (implement / devdocsimpact).
- Reconstructing client address / Host / trust hop (`IPCacheKey` / `GetRemoteIP` / `FamilyOfHostOrCIDR` stay the owners).

## Decisions

1. **Table on DecisionStore, not MetricsReporter.** Packed ids are shared-cache payload. Two Clients that reclaim the same store must see the same ids. Reporter holds compact slots and resolves names through the store. Alternative: reporter-owned table — rejected (reporter is per Client and is not a reclaim value). Alternative: package `var` — rejected (session-scoped).
2. **`uint16` ids, overflow stays on the `\x1f` string path, log once, do not wrap.** CAPI list cardinality is tens to hundreds. Alternative: `uint32` — rejected (ticket/explore assumed width). Alternative: evict or reuse ids — rejected (append-only).
3. **Memory ttl_map stores `uint32` (kind in the low 8 bits, origin id in the next 16).** `interface{}` already. String `Get`/`Set` stay for Redis, the stream lease, and the `range-index` blob. Memory Ip/header slots use a type-switch accessor (`uint32` vs leftover string). Alternative: format a U+001F string on every `Get` — rejected (explore). Alternative: 3-byte packed string behind `cacheInterface` — rejected (explore chose the word). Alternative: widen every cache get to `any` including Redis — rejected (Redis stays bytes of the origin string).
4. **Append-only slice published for lock-free reads.** Intern write takes a mutex, appends, publishes the new backing. Allow-path kind does not take that mutex. Alternative: read lock on every Get — rejected (ticket).
5. **Range: intern + pack before `ApplyRangeBatch` on the memory path.** `RangeMembership.storedByCIDR` holds packed (or leftover string) values. Redis `range-index` lines MAY keep the full suffix. Letter-only lines stay valid. Alternative: pack only per-IP — rejected (explore; same codec).
6. **Compact slot = origin id + family byte.** `rememberActiveDecision` interns then stores. Forget still keys the slot string. POST resolves id → `MetricsOrigin` and family → `ipv4`/`ipv6`. Overflow/empty origin keeps enough to send today's labels. Alternative: drop the slot map — rejected (ticket). Alternative: intern on the reporter — rejected (one table).
7. **Live/none stay on `RemediationWithOrigin`.** SessionHex includes mode. Do not pack live memo slots.
8. **No new public config. Keep ttl_map.**
9. **FindSpecHost as above.** New leaf plus three folds. Do not rename `decision-store`.

## Risks / Trade-offs

- [`cacheInterface` stays string while memory remediations are `uint32`] → Type-switch on the memory get path; do not stringify packed words on allow. Redis and lease keys unchanged.
- [Yaegi and `atomic.Pointer[T]`] → Publish the intern slice with `atomic.Value` (or equivalent already used on dest). Do not replace ttl_map with a Yaegi-hostile structure.
- [Overflow after 65535 names] → String path + one log. Gauge/drop labels stay correct. RSS regresses only for the overflow tail.
- [Range blob on memory is still a string document] → Membership holds the packed word; blob encoding may stay compact or string. RSS of `range-index` is CIDR-count, not 400K IPs.
- [Two Clients share ids only if they share the store] → Hang the table on DecisionStore at Open. Reporter receives a resolve view of that store, not a copy.

## Migration Plan

No operator JSON/YAML key change. In-memory maps rebuild on the next stream snapshot. Existing Redis keys stay `\x1f` strings and keep matching. Rollback is revert.

## Open Questions

None. Explore rows that stay assumed (coexist, overflow, range pack) are the proceed policy; propose did not change the choice, only the coexist wording on `explore.md`.
