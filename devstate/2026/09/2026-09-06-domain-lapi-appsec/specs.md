# Specs
change: separate-lapi-appsec-packages

verdicts:
  - { deltaId: lapi-connection, new, spec-id: core_plugin_lapi_connection, confidence: high, candidates: [core_plugin_lapi_usage-metrics, core_plugin_lapi_failure-action, core_plugin_connection_source-files] }
  - { deltaId: appsec-client, new, spec-id: core_plugin_appsec_client, confidence: high, candidates: [core_plugin_appsec_failure-action, core_plugin_appsec_bot-detection] }
  - { deltaId: instance-reclaim, fold, spec-id: core_plugin_middleware_instance-reclaim, confidence: high, candidates: [core_plugin_middleware_instance-reclaim] }
  - { deltaId: connection-source-files, fold, spec-id: core_plugin_connection_source-files, confidence: high, candidates: [core_plugin_connection_source-files] }
  - { deltaId: appsec-bot-detection, fold, spec-id: core_plugin_appsec_bot-detection, confidence: high, candidates: [core_plugin_appsec_bot-detection] }
  - { deltaId: appsec-failure-action, fold, spec-id: core_plugin_appsec_failure-action, confidence: high, candidates: [core_plugin_appsec_failure-action] }
  - { deltaId: lapi-failure-action, fold, spec-id: core_plugin_lapi_failure-action, confidence: high, candidates: [core_plugin_lapi_failure-action] }

- added core_plugin_lapi_connection
- added core_plugin_appsec_client
- modified core_plugin_middleware_instance-reclaim
- modified core_plugin_connection_source-files (REMOVED both requirements)
- modified core_plugin_appsec_bot-detection
- modified core_plugin_appsec_failure-action
- modified core_plugin_lapi_failure-action
