# Specs
change: lapi-appsec-failure-action
- added core_plugin_lapi_failure-action (new)
- added core_plugin_appsec_failure-action (new)
- modified core_plugin_appsec_bot-detection (fold)

FindSpecHost:
  - { deltaId: lapi-failure-action, new, spec-id: core_plugin_lapi_failure-action, confidence: high, candidates: [core_plugin_middleware_instance-reclaim] }
  - { deltaId: appsec-failure-action, new, spec-id: core_plugin_appsec_failure-action, confidence: high, candidates: [core_plugin_appsec_bot-detection] }
  - { deltaId: bot-detection-failure-wording, fold, spec-id: core_plugin_appsec_bot-detection, confidence: high, candidates: [core_plugin_appsec_bot-detection] }
