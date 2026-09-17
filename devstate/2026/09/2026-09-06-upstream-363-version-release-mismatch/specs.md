# Specs
change: assert-plugin-version-reporting

verdicts:
  - { deltaId: lapi-envelope-version, fold: fold, spec-id: core_plugin_lapi_usage-metrics, confidence: high, candidates: [core_plugin_lapi_usage-metrics, core_plugin_lapi_connection, core_plugin_middleware_instance-reclaim] }
  - { deltaId: appsec-user-agent, fold: fold, spec-id: core_plugin_appsec_client, confidence: high, candidates: [core_plugin_appsec_client, core_plugin_lapi_usage-metrics] }

- modified core_plugin_lapi_usage-metrics
- modified core_plugin_appsec_client
