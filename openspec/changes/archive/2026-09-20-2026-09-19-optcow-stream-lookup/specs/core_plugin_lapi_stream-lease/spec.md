## REMOVED Requirements

### Requirement: Stream poll lease TTL is at least one second
**Reason**: Stream lease dropped. Pollers on one Client do not overlap (intra-instance single-flight). Distinct pods are distinct CrowdSec rows (LAPI URL+key and the IP LAPI sees). Do not reintroduce `updated` / `Acquire`.
**Migration**: `handleStreamTicker` single-flight (`core_plugin_lapi_stream-single-flight`) is the in-process overlap guard. Redis replicas hydrate Range from `range-index`.

### Requirement: Stream lease acquire is atomic
**Reason**: Same as above. `cache.Client.Acquire` is deleted with `pkg/cache`.
**Migration**: None.

### Requirement: A failed poll releases the stream lease
**Reason**: There is no lease to release. A failed poll still leaves stream startup set so the retry asks for the full decision set (`core_plugin_lapi_stream-apply`).
**Migration**: Range apply failure still returns from `fetchAndApplyStreamDecisions` so startup stays set.
