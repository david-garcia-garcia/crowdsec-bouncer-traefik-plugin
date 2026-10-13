# Specs
change: crowdsec-decision-header

FindSpecHost:
- { deltaId: forced-decision-header, new, spec-id: core_plugin_middleware_forced-decision, confidence: high, candidates: [core_plugin_middleware_bouncer, core_plugin_middleware_captcha-routing, core_plugin_decisions_scopes] }
- { deltaId: lookup-exception, fold, spec-id: core_plugin_middleware_bouncer, confidence: high, candidates: [core_plugin_middleware_bouncer] }
- { deltaId: metrics-origin, fold, spec-id: core_plugin_lapi_usage-metrics, confidence: high, candidates: [core_plugin_lapi_usage-metrics] }

- added core_plugin_middleware_forced-decision
- modified core_plugin_middleware_bouncer
- modified core_plugin_lapi_usage-metrics
