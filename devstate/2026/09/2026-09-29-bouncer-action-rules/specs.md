# Specs
change: bouncer-action-rules
- fold core_plugin_middleware_bouncer (high) — request path + lists; remaining force-header behavior
- fold core_plugin_middleware_config-validation (high) — compile/empty/invalid `BouncerActionRules`
- fold core_plugin_middleware_forced-decision (high) — REMOVED-only; named capability gone
- fold core_plugin_lapi_usage-metrics (high) — origin `plugin:rules:<name>`
- skip none — Matching() is an internal helper; no httprule catalog leaf
