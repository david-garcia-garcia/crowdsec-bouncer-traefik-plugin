# Specs
change: bouncer-action-rules
- fold core_plugin_middleware_bouncer (high) — request path + lists; remaining force-header behavior
- fold core_plugin_middleware_config-validation (high) — compile/empty/invalid `BouncerActionRules`
- fold core_plugin_middleware_forced-decision (high) — REMOVED-only; named capability gone
- fold core_plugin_lapi_usage-metrics (high) — origin `plugin:rules:<name>`
- skip none — Matching() is an internal helper; no httprule catalog leaf

archive FindSpecHost:
- { deltaId: core_plugin_middleware_bouncer, fold, spec-id: core_plugin_middleware_bouncer, confidence: high, candidates: [core_plugin_middleware_bouncer, core_plugin_middleware_config-validation, core_plugin_middleware_forced-decision, core_plugin_httprule] }
- { deltaId: core_plugin_middleware_config-validation, fold, spec-id: core_plugin_middleware_config-validation, confidence: high, candidates: [core_plugin_middleware_config-validation, core_plugin_middleware_bouncer] }
- { deltaId: core_plugin_middleware_forced-decision, fold, spec-id: core_plugin_middleware_forced-decision, confidence: high, candidates: [core_plugin_middleware_forced-decision, core_plugin_middleware_bouncer] }
- { deltaId: core_plugin_lapi_usage-metrics, fold, spec-id: core_plugin_lapi_usage-metrics, confidence: high, candidates: [core_plugin_lapi_usage-metrics, core_plugin_middleware_bouncer] }
