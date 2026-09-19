## Why

Stream Ip and header decisions were optimized by bolting a third store onto `lapi.Client` (`liveTick`, `UsesLiveSnapshot`, bouncer snapshot-vs-cache branches) while apply still switches between that scratch map and `cache.Client.Set`. The backend (Redis vs memory) should be chosen once at `OpenDecisionStore`; `Client` should always mutate and look up through one stream store abstraction.

## What Changes

- Introduce a **stream store** on `DecisionStore` with Redis and memory implementations: Put, Delete, BeginTick, PublishTick, and request lookup for stream/alone Ip and header keys.
- **Redis** stream store delegates Put/Delete/Get to the existing `cache.Client`; BeginTick/PublishTick are no-ops.
- **Memory** stream store holds one copy-on-write `map[string]liveSlot{word, expiresAt}`; tick publishes once per successful stream apply; lookup Load-probes keys without TTL heap Set for those slots.
- Remove `Client.liveTick`, `UsesLiveSnapshot`, `LookupLiveSnapshotRemediation` wiring, and bouncer snapshot-vs-cache branching; stream apply and ServeHTTP always use the store.
- **Intern overflow** on the memory stream path: log Warn, store kind-only packed word (origin id 0); drop `LiveSlot.Leftover` and memory-path GetMany for overflow.
- **Unchanged this ticket:** `cache.Client` for stream lease, `range-index`, and live/none memo; no live/none packing onto the memory map; no Redis GetMany removal.
- **Delivery:** benchmarks and heap narrative vs **`origin/master`** (sequential + parallel miss, 100k fixture).
- **Implement replaces** the current branch bolt-on; do not extend it.

## Capabilities

### New Capabilities

_None — behavior folds into existing leaves._

### Modified Capabilities

- `core_cache_client_decision-store`: DecisionStore owns the stream Ip/header store (Redis vs memory); intern overflow on memory stream path is Warn + kind-only word, not leftover Set on slots.
- `core_plugin_lapi_stream-apply`: Non-Range Ip/header apply goes through stream store tick Put/Delete/Publish; no Client `liveTick` branch.
- `core_plugin_decisions_scopes`: Stream/alone request lookup reads the stream store and merges Range with ban-wins; memory path skips Range when Ip is already ban.
- `core_plugin_middleware_bouncer`: Stream/alone uses one Client lookup entry; no `UsesLiveSnapshot` branch.

## Impact

- `pkg/lapi/decisionstore.go`, new stream store types in `pkg/lapi/`
- `pkg/lapi/client_decisions.go`, `client_stream.go`, `client.go` — remove bolt-on fields/methods; delegate to store
- `pkg/decisionscope/` — stream lookup helper used by store/Client (merge with RangeMembership)
- `pkg/bouncer/bouncer.go` — single stream lookup call
- Tests/benchmarks replacing `liveTick` / live snapshot seeds; delivery card vs `origin/master`
- PR #118 target branch `master`
