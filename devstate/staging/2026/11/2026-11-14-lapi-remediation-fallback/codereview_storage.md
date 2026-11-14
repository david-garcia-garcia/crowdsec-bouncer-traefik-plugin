# Storage

## Stored data model
- DecisionStore (memory `ttl_map` and Redis, key prefix `SessionHex`): no new key, table, or field. The stream session payload hashed into `SessionHex` gains `remediationFallback` (`omitempty`, filled only when the effective `lapiRemediationFallback` is not `ban`). Omitted, empty, or `ban` keeps the pre-knob `SessionHex` and Redis key prefix; `captcha` or `ignore` forks to a new prefix that refills from LAPI with `startup=true`, and the old keys expire by TTL. No migration needed (derived identity, not a schema).
