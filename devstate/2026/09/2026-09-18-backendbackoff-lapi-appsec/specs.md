# Specs
change: backendbackoff-lapi-appsec

verdicts:
  - { deltaId: lapi-live-gate, fold|new: new, spec-id: core_plugin_lapi_backend-backoff, confidence: high, candidates: [core_plugin_lapi_connection, core_plugin_lapi_query-round-trip, core_plugin_lapi_failure-action, core_plugin_lapi_reclaim-key] }
  - { deltaId: appsec-query-gate, fold|new: new, spec-id: core_plugin_appsec_backend-backoff, confidence: high, candidates: [core_plugin_appsec_client, core_plugin_appsec_failure-action, core_plugin_appsec_bot-detection] }
  - { deltaId: shared-knobs-validate, fold|new: fold, spec-id: core_plugin_middleware_config-validation, confidence: high, candidates: [core_plugin_middleware_config-validation, core_plugin_middleware_bouncer] }

- added core_plugin_lapi_backend-backoff
- added core_plugin_appsec_backend-backoff
- modified core_plugin_middleware_config-validation

archive FindSpecHost (folder ids):
  - { deltaId: core_plugin_lapi_backend-backoff, fold|new: new, spec-id: core_plugin_lapi_backend-backoff, confidence: high, candidates: [core_plugin_lapi_connection, core_plugin_lapi_query-round-trip, core_plugin_lapi_failure-action, core_plugin_lapi_reclaim-key, core_plugin_lapi_backend-backoff] }
  - { deltaId: core_plugin_appsec_backend-backoff, fold|new: new, spec-id: core_plugin_appsec_backend-backoff, confidence: high, candidates: [core_plugin_appsec_client, core_plugin_appsec_failure-action, core_plugin_appsec_bot-detection, core_plugin_appsec_backend-backoff] }
  - { deltaId: core_plugin_middleware_config-validation, fold|new: fold, spec-id: core_plugin_middleware_config-validation, confidence: high, candidates: [core_plugin_middleware_config-validation, core_plugin_middleware_bouncer] }
