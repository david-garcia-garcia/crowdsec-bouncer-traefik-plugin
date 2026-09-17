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

archive FindSpecHost (folder ids; Task tool unavailable in this subagent — Search+Verdict on archive thread per find-spec-host.md):
  - { deltaId: core_plugin_lapi_reclaim-key, new, spec-id: core_plugin_lapi_reclaim-key, confidence: high, candidates: [core_plugin_middleware_instance-reclaim, core_plugin_lapi_connection, core_plugin_lapi_failure-action, core_plugin_lapi_stream-lease, std_go_reclaim_context-lease] }
  - { deltaId: core_plugin_middleware_bouncer, new, spec-id: core_plugin_middleware_bouncer, confidence: high, candidates: [core_plugin_middleware_instance-reclaim, core_plugin_lapi_failure-action] }
  - { deltaId: core_plugin_lapi_connection, fold, spec-id: core_plugin_lapi_connection, confidence: high, candidates: [core_plugin_lapi_connection, core_plugin_middleware_instance-reclaim] }
  - { deltaId: core_plugin_middleware_instance-reclaim, fold, spec-id: core_plugin_middleware_instance-reclaim, confidence: high, candidates: [core_plugin_middleware_instance-reclaim, core_plugin_middleware_bouncer] }
  - { deltaId: failure-action-per-router-dup, fold, spec-id: core_plugin_lapi_failure-action, confidence: high, candidates: [core_plugin_lapi_failure-action, core_plugin_middleware_instance-reclaim] }
sync: live catalog already matched ADDED/MODIFIED/REMOVED; no leftover catalog folder for retired instance-reclaim; no body rewrite on failure-action; archive history not rewritten.
