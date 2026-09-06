# Specs
change: appsec-unreadable-body-headers-only

FindSpecHost:
verdicts:
  - { deltaId: unreadable-stream-headers, fold: true, spec-id: core_plugin_appsec_failure-action, confidence: high, candidates: [core_plugin_appsec_failure-action, core_plugin_appsec_client, core_plugin_appsec_bot-detection] }

- modified core_plugin_appsec_failure-action

Archive FindSpecHost:
verdicts:
  - { deltaId: core_plugin_appsec_failure-action, fold: true, spec-id: core_plugin_appsec_failure-action, confidence: high, candidates: [core_plugin_appsec_failure-action, core_plugin_appsec_client, core_plugin_appsec_bot-detection] }
