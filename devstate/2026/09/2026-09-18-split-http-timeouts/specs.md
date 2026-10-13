# Specs
change: split-http-timeouts

FindSpecHost:
- { deltaId: inherit-knobs-and-validation, fold, spec-id: core_plugin_middleware_config-validation, confidence: high, candidates: [core_plugin_middleware_config-validation, core_plugin_middleware_bouncer] }
- { deltaId: lapi-effective-timeout-adopt, fold, spec-id: core_plugin_lapi_connection, confidence: high, candidates: [core_plugin_lapi_connection] }
- { deltaId: appsec-effective-timeout-query, fold, spec-id: core_plugin_appsec_client, confidence: high, candidates: [core_plugin_appsec_client] }
- { deltaId: timeout-out-of-reclaim-identity, fold, spec-id: core_plugin_lapi_reclaim-key, confidence: high, candidates: [core_plugin_lapi_reclaim-key, core_plugin_appsec_client] }
- { deltaId: captcha-siteverify-client-timeout, fold, spec-id: core_plugin_middleware_bouncer, confidence: high, candidates: [core_plugin_middleware_bouncer, core_plugin_middleware_captcha-siteverify] }

Archive FindSpecHost (delta folder ids; Task unavailable — ran on main thread):
- { deltaId: core_plugin_middleware_config-validation, fold, spec-id: core_plugin_middleware_config-validation, confidence: high, candidates: [core_plugin_middleware_config-validation, core_plugin_middleware_bouncer] }
- { deltaId: core_plugin_lapi_connection, fold, spec-id: core_plugin_lapi_connection, confidence: high, candidates: [core_plugin_lapi_connection] }
- { deltaId: core_plugin_appsec_client, fold, spec-id: core_plugin_appsec_client, confidence: high, candidates: [core_plugin_appsec_client] }
- { deltaId: core_plugin_lapi_reclaim-key, fold, spec-id: core_plugin_lapi_reclaim-key, confidence: high, candidates: [core_plugin_lapi_reclaim-key, core_plugin_appsec_client] }
- { deltaId: core_plugin_middleware_bouncer, fold, spec-id: core_plugin_middleware_bouncer, confidence: high, candidates: [core_plugin_middleware_bouncer, core_plugin_middleware_captcha-siteverify] }

- folded core_plugin_middleware_config-validation
- folded core_plugin_lapi_connection
- folded core_plugin_appsec_client
- folded core_plugin_lapi_reclaim-key
- folded core_plugin_middleware_bouncer
