## REMOVED Requirements

### Requirement: DecisionStore is a reclaim value that owns the cache
**Reason**: Removed unit. `pkg/cache` / `cache.Client` is deleted. Remaining unit is `pkg/decisionstore.Store` (`core_plugin_decisionstore_store`).
**Migration**: Call Store Open / Put / Lookup / Close. Archive folders keep this historical id.

### Requirement: Store key is cursor plus Redis store parameters
**Reason**: Restated on `core_plugin_decisionstore_store`.
**Migration**: Same reclaim key spelling (`decisionstore:` + SessionHex + Redis hash).

### Requirement: Cache prefix is SessionHex for every mode
**Reason**: Restated on `core_plugin_decisionstore_store`. Stream lease key is gone.
**Migration**: Redis keys stay prefixed with SessionHex.

### Requirement: Client Close does not dispose a shared store
**Reason**: Restated on `core_plugin_decisionstore_store` without `Cache()`.
**Migration**: Reclaim Close still disposes Redis; Client Close does not.

### Requirement: Cache payloads stay opaque strings
**Reason**: `pkg/cache` Get/Set/GetInt leftover path is deleted. Store engines own packed words (memory) and `KindOriginString` (Redis).
**Migration**: Look up through `Store.LookupRemediation`. Errors stay `store:miss` / `store:unreachable`.

### Requirement: DecisionStore owns the origin intern table
**Reason**: Restated on `core_plugin_decisionstore_store`. Overflow leftover strings are deleted (Warn + origin id 0).
**Migration**: Intern table stays on Store; Pack lives in `pkg/decisionstore`.

### Requirement: Stream and live write TTLs stay split
**Reason**: Restated on `core_plugin_decisionstore_store`.
**Migration**: Stream uses CrowdSec duration seconds; live uses `liveCacheTTL`.
