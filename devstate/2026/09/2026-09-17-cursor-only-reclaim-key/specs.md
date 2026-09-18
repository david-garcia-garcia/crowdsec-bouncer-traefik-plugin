# Specs
change: cursor-only-reclaim-key

FindSpecHost (propose, before each folder write):

```
verdicts:
  - { deltaId: cursor-shaped-client-key, fold, spec-id: core_plugin_lapi_reclaim-key, confidence: high, candidates: [core_plugin_lapi_reclaim-key, core_plugin_lapi_stream-lease, core_plugin_middleware_bouncer] }
  - { deltaId: delete-peek-import-utilities, fold, spec-id: std_go_reclaim_context-lease, confidence: high, candidates: [std_go_reclaim_context-lease] }
  - { deltaId: live-router-scope-union, new, spec-id: core_plugin_lapi_scope-union, confidence: high, candidates: [core_plugin_decisions_scopes, core_cache_client_decision-store, core_plugin_lapi_reclaim-key] }
  - { deltaId: stream-asks-mapped-scopes, fold, spec-id: core_plugin_decisions_scopes, confidence: high, candidates: [core_plugin_decisions_scopes, core_plugin_lapi_scope-union] }
  - { deltaId: store-filter-follows-union, fold, spec-id: core_cache_client_decision-store, confidence: high, candidates: [core_cache_client_decision-store, core_plugin_lapi_scope-union] }
```

- added core_plugin_lapi_scope-union
- modified core_plugin_lapi_reclaim-key
- modified std_go_reclaim_context-lease
- modified core_plugin_decisions_scopes
- modified core_cache_client_decision-store

FindSpecHost (archive, per delta folder id):

```
verdicts:
  - { deltaId: core_plugin_lapi_reclaim-key, fold, spec-id: core_plugin_lapi_reclaim-key, confidence: high, candidates: [core_plugin_lapi_reclaim-key, core_plugin_lapi_stream-lease, core_plugin_middleware_bouncer] }
  - { deltaId: std_go_reclaim_context-lease, fold, spec-id: std_go_reclaim_context-lease, confidence: high, candidates: [std_go_reclaim_context-lease] }
  - { deltaId: core_plugin_lapi_scope-union, new, spec-id: core_plugin_lapi_scope-union, confidence: high, candidates: [core_plugin_decisions_scopes, core_cache_client_decision-store, core_plugin_lapi_reclaim-key] }
  - { deltaId: core_plugin_decisions_scopes, fold, spec-id: core_plugin_decisions_scopes, confidence: high, candidates: [core_plugin_decisions_scopes, core_plugin_lapi_scope-union] }
  - { deltaId: core_cache_client_decision-store, fold, spec-id: core_cache_client_decision-store, confidence: high, candidates: [core_cache_client_decision-store, core_plugin_lapi_scope-union] }
```
