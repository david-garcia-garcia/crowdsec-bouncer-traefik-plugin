## REMOVED Requirements

### Requirement: Memory cache is per Client not process-wide
**Reason**: Isolation is by DecisionStore key, not per `lapi.Client` incarnation.
**Migration**: `core_cache_client_decision-store`. Memory remains per store map, not a process-wide TTL map.

### Requirement: Redis keys are prefixed with session identity for stream
**Reason**: Prefix is `SessionHex` for every mode on the shared store, not live `IdentityHex`.
**Migration**: `core_cache_client_decision-store`.

### Requirement: Stream lease is per stream session
**Reason**: The lease key lives in the DecisionStore space; atomic acquire is the stream-lease job.
**Migration**: `core_cache_client_decision-store` for isolation; `core_plugin_lapi_stream-lease` for acquire.

### Requirement: Cache payloads are opaque strings
**Reason**: Opaque payloads stay; the owner leaf is the remapped store.
**Migration**: `core_cache_client_decision-store`.
