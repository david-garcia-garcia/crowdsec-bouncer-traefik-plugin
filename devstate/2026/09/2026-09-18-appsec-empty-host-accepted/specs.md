# Specs
change: reject-empty-appsec-host-when-enabled
- modified core_plugin_middleware_config-validation

FindSpecHost:
- { deltaId: reject-empty-appsec-host-when-enabled, fold, spec-id: core_plugin_middleware_config-validation, confidence: high, candidates: [core_plugin_middleware_config-validation, core_plugin_appsec_client, core_plugin_appsec_failure-action, core_plugin_middleware_bouncer] }
- { deltaId: core_plugin_middleware_config-validation, fold, spec-id: core_plugin_middleware_config-validation, confidence: high, candidates: [core_plugin_middleware_config-validation, core_plugin_appsec_client, core_plugin_appsec_failure-action, core_plugin_middleware_bouncer, core_plugin_appsec_bot-detection, reject-empty-appsec-host-when-enabled] }
