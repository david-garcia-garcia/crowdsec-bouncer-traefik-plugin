# Specs
change: shared-decision-store

verdicts:
  - { deltaId: decision-store, new, core_cache_client_decision-store, confidence: high, candidates: [core_cache_client_isolated-store, core_plugin_lapi_reclaim-key, std_go_reclaim_context-lease] }
  - { deltaId: isolated-store-removed, fold, core_cache_client_isolated-store, confidence: high, candidates: [core_cache_client_isolated-store] }
  - { deltaId: stream-lease-atomic, fold, core_plugin_lapi_stream-lease, confidence: high, candidates: [core_plugin_lapi_stream-lease, core_cache_client_isolated-store] }
  - { deltaId: reclaim-key-readhosts, fold, core_plugin_lapi_reclaim-key, confidence: high, candidates: [core_plugin_lapi_reclaim-key] }
  - { deltaId: cache-acquire-eval, fold, core_cache_redis_utilities-client, confidence: high, candidates: [core_cache_redis_utilities-client] }

- added core_cache_client_decision-store (new; Removed unit rename from isolated-store)
- modified core_cache_client_isolated-store (fold; REMOVED)
- modified core_plugin_lapi_stream-lease (fold)
- modified core_plugin_lapi_reclaim-key (fold)
- modified core_cache_redis_utilities-client (fold)
