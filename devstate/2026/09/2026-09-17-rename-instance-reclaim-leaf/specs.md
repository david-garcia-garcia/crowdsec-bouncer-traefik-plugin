# Specs
change: rename-instance-reclaim-leaf

verdicts:
  - { deltaId: lapi-reclaim-key, new, spec-id: core_plugin_lapi_reclaim-key, confidence: high, candidates: [core_plugin_middleware_instance-reclaim, core_plugin_lapi_connection, core_plugin_lapi_failure-action, core_plugin_lapi_stream-lease, std_go_reclaim_context-lease] }
  - { deltaId: middleware-bouncer, new, spec-id: core_plugin_middleware_bouncer, confidence: high, candidates: [core_plugin_middleware_instance-reclaim, core_plugin_lapi_failure-action] }
  - { deltaId: transport-adopt-concurrent, fold, spec-id: core_plugin_lapi_connection, confidence: high, candidates: [core_plugin_lapi_connection, core_plugin_middleware_instance-reclaim] }
  - { deltaId: failure-action-per-router-dup, fold, spec-id: core_plugin_lapi_failure-action, confidence: high, candidates: [core_plugin_lapi_failure-action, core_plugin_middleware_instance-reclaim] }
  - { deltaId: instance-reclaim-retire, fold, spec-id: core_plugin_middleware_instance-reclaim, confidence: high, candidates: [core_plugin_middleware_instance-reclaim, core_plugin_middleware_bouncer] }

- added core_plugin_lapi_reclaim-key
- added core_plugin_middleware_bouncer
- modified core_plugin_lapi_connection
- folded core_plugin_lapi_failure-action (no body rewrite; dump dups dropped)
- modified core_plugin_middleware_instance-reclaim (REMOVED; live folder deleted at apply/archive)
