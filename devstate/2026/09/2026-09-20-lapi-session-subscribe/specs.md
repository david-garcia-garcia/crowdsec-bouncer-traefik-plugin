# Specs
change: 2026-09-20-lapi-session-subscribe
- modified core_plugin_lapi_reclaim-key
- modified core_plugin_decisionstore_store
- modified core_plugin_middleware_bouncer
- modified core_plugin_lapi_connection

FindSpecHost:

```
verdicts:
  - { deltaId: stream-session-subscribe, fold, spec-id: core_plugin_lapi_reclaim-key, confidence: high, candidates: [core_plugin_lapi_reclaim-key, core_plugin_lapi_connection, core_plugin_middleware_bouncer, std_go_reclaim_context-lease] }
  - { deltaId: store-child-of-client, fold, spec-id: core_plugin_decisionstore_store, confidence: high, candidates: [core_plugin_decisionstore_store, core_plugin_lapi_reclaim-key] }
  - { deltaId: new-bind-opens, fold, spec-id: core_plugin_middleware_bouncer, confidence: high, candidates: [core_plugin_middleware_bouncer, core_plugin_decisionstore_store] }
  - { deltaId: lifecycle-info, fold, spec-id: core_plugin_lapi_connection, confidence: high, candidates: [core_plugin_lapi_connection, core_plugin_lapi_reclaim-key] }
```

Search also ranked `std_go_reclaim_context-lease` (table state / no Peek already specified), `core_plugin_lapi_scope-union` (header union stays), and `core_plugin_lapi_usage-metrics` (per-Client reporter stays). No deltas there. No new 4th part. Change kebab was not used as a leaf.
