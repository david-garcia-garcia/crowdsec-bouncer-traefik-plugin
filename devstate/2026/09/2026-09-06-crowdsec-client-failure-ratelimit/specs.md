# Specs
change: crowdsec-client-failure-backoff

FindSpecHost:
- { deltaId: tracker, new, spec-id: core_plugin_health_tracker, confidence: high, candidates: [none] }
- { deltaId: lapi-backoff, new, spec-id: core_plugin_lapi_failure-backoff, confidence: high, candidates: [core_plugin_lapi_failure-action, core_plugin_lapi_connection] }
- { deltaId: appsec-backoff, new, spec-id: core_plugin_appsec_failure-backoff, confidence: high, candidates: [core_plugin_appsec_failure-action, core_plugin_appsec_client] }
- { deltaId: appsec-identity, fold, spec-id: core_plugin_appsec_client, confidence: high, candidates: [core_plugin_appsec_client] }

- added core_plugin_health_tracker
- added core_plugin_lapi_failure-backoff
- added core_plugin_appsec_failure-backoff
- modified core_plugin_appsec_client
