# Specs
change: upstream-reclaim-simpleredis
- added core_cache_redis_utilities-client
- modified std_go_reclaim_context-lease
- modified core_plugin_appsec_client
- modified core_plugin_middleware_instance-reclaim
- removed core_cache_redis_in-tree-client (rename; leaf named deleted pkg/simpleredis)

archive FindSpecHost:
- { deltaId: core_cache_redis_utilities-client, new, spec-id: core_cache_redis_utilities-client, confidence: high }
- { deltaId: std_go_reclaim_context-lease, fold, spec-id: std_go_reclaim_context-lease, confidence: high }
- { deltaId: core_plugin_appsec_client, fold, spec-id: core_plugin_appsec_client, confidence: high }
- { deltaId: core_plugin_middleware_instance-reclaim, fold, spec-id: core_plugin_middleware_instance-reclaim, confidence: high }
