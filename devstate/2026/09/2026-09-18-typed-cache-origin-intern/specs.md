# Specs
change: typed-cache-origin-intern
- fold core_cache_client_decision-store
- fold core_plugin_decisions_scopes
- fold core_plugin_lapi_usage-metrics
- fold core_cache_redis_utilities-client
archive FindSpecHost (reused propose):
- { deltaId: core_cache_client_decision-store, fold, spec-id: core_cache_client_decision-store, confidence: high }
- { deltaId: core_plugin_decisions_scopes, fold, spec-id: core_plugin_decisions_scopes, confidence: high }
- { deltaId: core_plugin_lapi_usage-metrics, fold, spec-id: core_plugin_lapi_usage-metrics, confidence: high }
- { deltaId: core_cache_redis_utilities-client, fold, spec-id: core_cache_redis_utilities-client, confidence: medium }
