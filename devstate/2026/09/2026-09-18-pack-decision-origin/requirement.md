# Requirement
IssueKey: 2026-09-18-pack-decision-origin

## Problem
Stream/alone in-memory storage at ~400K IP decisions keeps each usage-metrics origin string twice: once in the ttl_map value (`kind` + U+001F + origin) and once in `MetricsReporter.activeDecisionSlots` as a five-string `usageMetricKey`. Probe RSS is ~113 MiB; the operator wants that RSS down without a public config knob.

## Current (code)
- `RemediationWithOrigin` concatenates letter + `\x1f` + origin; `RemediationKind` takes `stored[:1]`; `RemediationOrigin` splits on `\x1f`. `pkg/cache/remediation.go`
- Stream IP/header write: `MetricsOrigin` then `RemediationWithOrigin` then `cache.Set` and `rememberActiveDecision`. `pkg/lapi/client_decisions.go`
- Stream Range write: same `RemediationWithOrigin` into `rangeUpserts` and `rememberActiveDecision("range:"+cidr, ...)`. `pkg/lapi/client_stream.go`
- `LookupCachedRemediation` always returns `RemediationKind` + `RemediationOrigin` of the winning stored string. `pkg/decisionscope/lookup.go`
- Stream/alone request path passes that origin into remediation; `recordDropped` → `IncDropped(origin string, ...)`. `pkg/bouncer/bouncer.go`
- Live lookup also splits origin from the stored/live string via `RemediationOrigin`. `pkg/bouncer/bouncer.go`
- `usageMetricKey` is five strings (`name`, `unit`, `origin`, `ipType`, `remediation`). `pkg/lapi/client_metrics.go`
- `activeDecisionSlots` is `map[string]usageMetricKey`; remember copies the origin string and `ip.FamilyOfHostOrCIDR` (`"ipv4"` / `"ipv6"`). `pkg/lapi/client_metrics.go` `pkg/ip/network.go`
- Forget needs the per-slot entry; ticket forbids deleting the map. `pkg/lapi/client_metrics.go`
- `MetricsReporter` is allocated in `Client.New`; `Client` is the session reclaim value. `pkg/lapi/client.go` `pkg/lapi/session.go`
- `DecisionStore` is a separate reclaim value that owns `cache.Client` (ttl_map or Redis). `pkg/lapi/decisionstore.go`
- `cacheInterface` get/set is `string`; `localCache` stores that string in `ttl_map.Heap`; Redis writes `[]byte(value)`. `pkg/cache/cache.go`
- Origin intern / packed cache value / compact slot record: not found.
- No packing or intern public config field. `pkg/configuration/configuration.go`

## Desired
- Append-only origin dictionary: first seen `MetricsOrigin` string gets the next numeric id; reverse map on the stream write path. Kind letters `t`/`c`/`f`/`d` stay raw ASCII. `ip_type` may be a byte (`4`/`6`).
- In-memory cache value is kind byte + origin id, not a per-decision origin string. Request path extracts kind by shift/mask; resolve `table[id]` only when reporting a drop. No second lock on `cache.Get`. Intern reads lock-free (append-only table).
- Compact `activeDecisionSlots` the same way (`originID` + family) using that same table.
- Table lives on the DecisionStore / MetricsReporter reclaim value for that LAPI session. Not a package `var`. Not shared across sessions.
- Redis may keep writing the full origin string. No shared Redis intern table. Memory path may differ from Redis behind `cacheInterface`.
- Keep ttl_map (no custom IP-as-bytes maps). Keep `activeDecisionSlots` (per-slot forget). No new public config.

## Affected
- `pkg/cache/remediation.go` and memory `localCache` / `cacheInterface` if the packed value is not a `\x1f` string
- `pkg/lapi/client_decisions.go`, `pkg/lapi/client_stream.go` (intern on write)
- `pkg/decisionscope/lookup.go`, `pkg/bouncer/bouncer.go` (kind vs origin resolve-on-drop)
- `pkg/lapi/client_metrics.go` (`activeDecisionSlots`, intern ownership)
- `pkg/lapi/decisionstore.go` / `pkg/lapi/client.go` if the table is hung on the reclaim value
- Tests under `pkg/cache`, `pkg/lapi`, `pkg/decisionscope`, `pkg/bouncer`

## Out of scope
- Redis intern table or changing Redis payload size
- Replacing ttl_map or introducing custom IP-as-bytes maps
- Dropping `activeDecisionSlots`
- New public config
- AppSec, captcha, live/none LAPI query shape (live still stores `\x1f` strings today; packing is only required for stream/alone in-memory RSS)
- Yaegi-sensitive map replacement

## Unknowns
- Exact reclaim owner: `DecisionStore` (shared across live interval splits) vs `MetricsReporter` on the reclaimed `Client` (one per session key). Ticket names both.
- How packed memory values coexist with string `cacheInterface` and Redis full-string writes without a second lock on `Get`.
- Origin-id width (uint16 vs uint32) and overflow when list names are many (`lists:<scenario>`).
- Whether Range blob lines in `range-index` pack the same way as per-IP ttl_map values (they share `RemediationWithOrigin` today).
- Probe RSS numbers (113 / 96 / 54 MiB) are caller-measured; not reproduced this prepare.

## Tensions
- Ticket wants a non-string packed cache value; dest `cacheInterface` is string for both backends.
- Ticket wants `table[id]` only on drop; dest lookup always returns an origin string.
- Ticket wants kind via shift/mask; dest `RemediationKind` is `stored[:1]` on a string.
- Ticket says table on DecisionStore / MetricsReporter; dest MetricsReporter is not its own reclaim object.
- Ticket title is stream-mode; live memory cache uses the same `RemediationWithOrigin` codec.
