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

archive-reverify (2026-09-17; Task unavailable in archive runner — Search+Verdict on-thread):
verdicts:
  - { deltaId: core_plugin_middleware_instance-reclaim, fold|new: fold, spec-id: core_plugin_middleware_instance-reclaim, confidence: high, candidates: [core_plugin_middleware_instance-reclaim, core_plugin_lapi_connection, core_plugin_lapi_failure-action, core_plugin_lapi_stream-lease] }
  - { deltaId: core_plugin_lapi_failure-action, fold|new: fold, spec-id: core_plugin_lapi_failure-action, confidence: high, candidates: [core_plugin_lapi_failure-action, core_plugin_middleware_instance-reclaim, core_plugin_appsec_failure-action] }
  - { deltaId: core_plugin_lapi_connection, fold|new: fold, spec-id: core_plugin_lapi_connection, confidence: high, candidates: [core_plugin_lapi_connection, core_plugin_middleware_instance-reclaim] }
