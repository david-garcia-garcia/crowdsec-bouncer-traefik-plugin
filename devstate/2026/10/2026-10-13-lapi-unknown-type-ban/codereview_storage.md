# Storage

## Stored data model
- Redis cache (when Redis cache is enabled): unknown LAPI decision keys now persist payload `t` (ban) instead of an empty string. Same key, same TTL. No schema or field change. Memory cache is process-local.
