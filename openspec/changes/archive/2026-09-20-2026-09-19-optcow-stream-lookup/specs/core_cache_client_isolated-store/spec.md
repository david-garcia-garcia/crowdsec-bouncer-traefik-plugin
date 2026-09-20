## REMOVED Requirements

### Requirement: Isolated cache key space per session
**Reason**: `pkg/cache` is deleted. Isolation is SessionHex prefix on the `pkg/decisionstore` Redis engine (`core_plugin_decisionstore_store`). Stream lease is dropped.
**Migration**: Two sessions still do not observe each other’s remediations: different Store incarnations and Redis prefixes. Archive folders keep this historical id.
