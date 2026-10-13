## REMOVED Requirements

### Requirement: Vendored utilities client is the Redis client
**Reason**: Remaining Redis client is the decisionstore Redis engine (`core_plugin_decisionstore_store`). `pkg/cache/cache.go` is deleted.
**Migration**: Inspect `pkg/decisionstore/redis.go`. Utilities SimpleRedis import and `v1.0.5` stay.

### Requirement: Client is constructed with New and explicit timeouts
**Reason**: Construction lives on `NewRedis` / `newRedis` in `pkg/decisionstore`.
**Migration**: Same dial 2s / command 1s / idle 30s / pool 8.

### Requirement: Pooled client is not copied by value
**Reason**: Restated on the store Redis engine (writer and readers are pointers).
**Migration**: None.

### Requirement: Commands pass a context
**Reason**: Restated on the store Redis engine (`context.Background()`).
**Migration**: None.

### Requirement: Close stops new dials
**Reason**: Restated on the store Redis engine Close hook.
**Migration**: None.

### Requirement: Miss and unreachable map through helpers or equal strings
**Reason**: Restated on the store (`store:miss` / `store:unreachable`).
**Migration**: Callers use `errors.Is` on `decisionstore.ErrMiss` / `ErrUnreachable`.

### Requirement: Cache Client exposes a narrow lease acquire
**Reason**: Stream lease dropped. Pollers do not overlap; pods are distinct by LAPI+IP. Do not reintroduce `cache.Client.Acquire`.
**Migration**: Intra-instance single-flight is `core_plugin_lapi_stream-single-flight`.

### Requirement: Redis Int uses existing byte Set and Get
**Reason**: Redis slots are `KindOriginString`, not decimal `uint32` GetInt. Leftover strings are deleted.
**Migration**: Redis Put writes kind + newline + origin.

### Requirement: Get uses nextReader only
**Reason**: Restated on `core_plugin_decisionstore_store`.
**Migration**: Replica miss or error is not retried on the writer.

### Requirement: Set and Delete are void
**Reason**: Restated on `core_plugin_decisionstore_store`.
**Migration**: Put/Delete log Redis errors and return.

### Requirement: Redis SET EX uses the duration as given
**Reason**: Restated on `core_plugin_decisionstore_store`.
**Migration**: Duration `0` still sends `EX 0`.
