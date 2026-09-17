# Specs
change: lapi-transport-router-policy

verdicts:
  - { deltaId: settings-hash-and-last-wins-transport, fold|new: fold, spec-id: core_plugin_middleware_instance-reclaim, confidence: high, candidates: [core_plugin_middleware_instance-reclaim, core_plugin_lapi_connection, core_plugin_lapi_failure-action, core_plugin_lapi_stream-lease] }
  - { deltaId: failure-action-owner-on-bouncer, fold|new: fold, spec-id: core_plugin_lapi_failure-action, confidence: high, candidates: [core_plugin_lapi_failure-action, core_plugin_middleware_instance-reclaim, core_plugin_appsec_failure-action] }
  - { deltaId: bouncer-holds-redis-fail-closed-and-live-ttl, fold|new: fold, spec-id: core_plugin_middleware_instance-reclaim, confidence: high, candidates: [core_plugin_middleware_instance-reclaim, core_plugin_lapi_failure-action] }
  - { deltaId: transport-extract-atomic-value, fold|new: fold, spec-id: core_plugin_lapi_connection, confidence: high, candidates: [core_plugin_lapi_connection, core_plugin_middleware_instance-reclaim] }

- folded core_plugin_middleware_instance-reclaim
- folded core_plugin_lapi_failure-action
- folded core_plugin_lapi_connection
