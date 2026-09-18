## Why

Stream/alone in-memory storage at ~400K IP decisions keeps each usage-metrics origin string twice (ttl_map `RemediationWithOrigin` concat and `activeDecisionSlots` `usageMetricKey`). Probe RSS is ~113 MiB; the operator wants that RSS down without a public config knob.

## What Changes

- Append-only origin dictionary on the DecisionStore reclaim value: first-seen `MetricsOrigin` string gets the next `uint16` id. Not a package `var`. Not shared across sessions. Two Clients that reclaim the same store share ids.
- Stream/alone memory Ip/header (and Range membership) values store kind letter + origin id as a packed word. Kind is shift/mask on the allow path. Resolve `table[id]` only on drop / metrics POST. Overflow (`uint16` full) stays on the existing `\x1f` string path and logs once.
- Compact `activeDecisionSlots` values to origin id + family using that same table. Keep the per-slot map (forget still needs it).
- Redis keeps writing full `RemediationWithOrigin` strings. No Redis intern table. Live/none stay on the string codec.
- Keep ttl_map. No custom IP-as-bytes maps. No new public config.

## Capabilities

### New Capabilities

- `core_cache_client_origin-dictionary`: DecisionStore-owned append-only origin intern table and packed memory remediation values (kind + `uint16` id). Redis and live/none stay on the string codec.

### Modified Capabilities

- `core_cache_client_decision-store`: memory remediation slots MAY store a packed word; Redis and non-remediation keys stay opaque strings.
- `core_plugin_decisions_scopes`: lookup extracts kind without resolving origin on the allow path; packed memory values (including Range membership) still match; Redis `\x1f` suffix and letter-only lines stay valid.
- `core_plugin_lapi_usage-metrics`: `activeDecisionSlots` store origin id + family; POST still sends the origin string and `ipv4`/`ipv6` labels.

## Impact

- `pkg/lapi/decisionstore.go` (table ownership), `pkg/lapi/client_decisions.go`, `pkg/lapi/client_stream.go` (intern + pack on stream/alone write).
- `pkg/cache/cache.go` / `pkg/cache/remediation.go` (packed word in ttl_map; Redis string writes).
- `pkg/decisionscope/lookup.go`, `pkg/decisionscope/rangemembership.go`, `pkg/bouncer/bouncer.go` (kind vs resolve-on-drop).
- `pkg/lapi/client_metrics.go` (compact slots; resolve through the store table).
- Tests under `pkg/cache`, `pkg/lapi`, `pkg/decisionscope`, `pkg/bouncer`.
- Usage packets `knowledge/devdocs/core_cache_client.md`, `core_plugin_lapi_usage-metrics.md`, `core_plugin_decisionscope.md` after apply (devdocsimpact).
- No **BREAKING** public JSON/YAML keys.
- Out of scope: Redis intern table, replacing ttl_map, dropping `activeDecisionSlots`, AppSec, captcha, live/none LAPI query shape, Yaegi-sensitive map replacement.
