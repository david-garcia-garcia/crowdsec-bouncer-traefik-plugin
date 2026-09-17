## REMOVED Requirements

### Requirement: Vendored utilities client is the Redis client
**Reason**: Plugin no longer ships a Redis cache path.
**Migration**: Use per-process memory cache only; drop Redis/Dragonfly from deployment.

### Requirement: Client is constructed with New and explicit timeouts
**Reason**: Redis cache backend removed.
**Migration**: N/A — configuration keys removed.

### Requirement: Pooled client is not copied by value
**Reason**: Redis cache backend removed.
**Migration**: N/A.

### Requirement: Commands pass a context
**Reason**: Redis cache backend removed.
**Migration**: N/A.

### Requirement: Close stops new dials
**Reason**: Redis cache backend removed.
**Migration**: N/A.

### Requirement: Miss and unreachable map through helpers or equal strings
**Reason**: Redis cache backend removed.
**Migration**: Memory cache still returns `cache:miss` and `cache:unreachable` where applicable.
