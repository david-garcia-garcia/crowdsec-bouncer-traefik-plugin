# Specs
change: serialize-stream-poll

verdicts:
  - { deltaId: one-inflight-stream-poll, fold, spec-id: core_plugin_middleware_instance-reclaim, confidence: high, candidates: [core_plugin_middleware_instance-reclaim, core_plugin_lapi_connection] }
  - { deltaId: crowdsec-query-timeout, fold, spec-id: core_plugin_lapi_connection, confidence: medium, candidates: [core_plugin_lapi_connection, core_plugin_lapi_failure-action, core_plugin_middleware_instance-reclaim] }

- modified core_plugin_middleware_instance-reclaim
- modified core_plugin_lapi_connection
