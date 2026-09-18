# Specs
change: cache-accepted-semantics

FindSpecHost:

```
verdicts:
  - { deltaId: replica-lag-reads, fold|new: fold, spec-id: core_cache_redis_utilities-client, confidence: high, candidates: [core_cache_redis_utilities-client, core_cache_client_decision-store, core_cache_client_isolated-store] }
  - { deltaId: void-set-delete, fold|new: fold, spec-id: core_cache_redis_utilities-client, confidence: high, candidates: [core_cache_redis_utilities-client, core_cache_client_decision-store] }
  - { deltaId: ex-as-given, fold|new: fold, spec-id: core_cache_redis_utilities-client, confidence: high, candidates: [core_cache_redis_utilities-client, core_cache_client_decision-store] }
  - { deltaId: stream-vs-live-ttl, fold|new: fold, spec-id: core_cache_client_decision-store, confidence: medium, candidates: [core_cache_client_decision-store, core_plugin_lapi_stream-apply, core_plugin_lapi_connection, core_cache_redis_utilities-client, core_cache_client_isolated-store] }
```

- modified core_cache_redis_utilities-client
- modified core_cache_client_decision-store

archive FindSpecHost (delta folder ids; Task unavailable on archive worker — ran find-spec-host.md on this thread):
```
verdicts:
  - { deltaId: core_cache_redis_utilities-client, fold|new: fold, spec-id: core_cache_redis_utilities-client, confidence: high, candidates: [core_cache_redis_utilities-client, core_cache_client_decision-store, core_cache_client_isolated-store] }
  - { deltaId: core_cache_client_decision-store, fold|new: fold, spec-id: core_cache_client_decision-store, confidence: medium, candidates: [core_cache_client_decision-store, core_plugin_lapi_stream-apply, core_plugin_lapi_connection, core_cache_redis_utilities-client, core_cache_client_isolated-store] }
```
