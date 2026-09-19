# Devdocs impact
change: typed-cache-origin-intern

## Units
- DecisionStore cache — subsystem — knowledge/devdocs/core_cache_client.md
- Redis cache client — subsystem — knowledge/devdocs/core_cache_redis.md
- Decision scopes — subsystem — knowledge/devdocs/core_plugin_decisionscope.md
- LAPI usage-metrics — subsystem — knowledge/devdocs/core_plugin_lapi_usage-metrics.md

## Findings
- [x] language-gap  Typed bag / origin intern / packed word — `core_cache_client` has How-to, no Language terms
- [x] language-gap  Leftover remediation / packed range line — `core_plugin_decisionscope` Range index Language omits packed letter+id
- [x] stale-usage  Lookup leftover I/O — `core_plugin_decisionscope` and `core_cache_redis` still imply GetMany on every key
- [x] language-gap  Compact slot — `core_plugin_lapi_usage-metrics` How-to has originID+family, no Language term
- [x] stale-usage  Usage-metrics snippet still `IncDropped(RemediationOrigin(stored))` without originID
