# Specs
Change: remove-redis-cache

FindSpecHost verdicts (per delta folder):

| deltaId | verdict | spec-id | confidence | candidates |
|---------|---------|---------|------------|------------|
| core_cache_client_isolated-store | fold | core_cache_client_isolated-store | high | core_cache_client_isolated-store, core_cache_redis_utilities-client |
| core_cache_redis_utilities-client | fold | core_cache_redis_utilities-client | high | core_cache_redis_utilities-client (retire leaf at archive) |
| build_e2e_mock_redis-resp | fold | build_e2e_mock_redis-resp | high | build_e2e_mock_redis-resp |
| build_e2e_pester_crowdsec-stack | fold | build_e2e_pester_crowdsec-stack | high | build_e2e_pester_crowdsec-stack |
| core_plugin_middleware_instance-reclaim | fold | core_plugin_middleware_instance-reclaim | high | core_plugin_middleware_instance-reclaim |
| core_plugin_decisions_scopes | fold | core_plugin_decisions_scopes | high | core_plugin_decisions_scopes |

Added: (none)

Modified:
- core_cache_client_isolated-store
- core_cache_redis_utilities-client (REMOVED requirements — leaf retired at archive)
- build_e2e_mock_redis-resp (REMOVED — leaf retired at archive)
- build_e2e_pester_crowdsec-stack
- core_plugin_middleware_instance-reclaim
- core_plugin_decisions_scopes
