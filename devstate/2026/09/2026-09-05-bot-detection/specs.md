# Specs
change: appsec-bot-detection

FindSpecHost:
- delta appsec-structured-relay → new `core_plugin_appsec_bot-detection` (high; candidates `core_plugin_middleware_instance-reclaim`, `core_plugin_decisions_scopes`)
- delta real-e2e-bot-detection → fold `build_e2e_pester_crowdsec-stack` (high)
- delta mock-json-appsec → no separate spec (small adjustment under the product leaf + existing mock appsec scenario)

- added core_plugin_appsec_bot-detection
- modified build_e2e_pester_crowdsec-stack
