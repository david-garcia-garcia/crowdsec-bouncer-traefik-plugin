# Specs
change: intern-decision-scenario
- added core_plugin_decisionstore_store
- added core_plugin_lapi_usage-metrics

FindSpecHost:
- { deltaId: packed-word-and-intern, fold, spec-id: core_plugin_decisionstore_store, confidence: high, candidates: [core_plugin_decisionstore_store, core_plugin_lapi_usage-metrics, core_plugin_lapi_stream-apply, core_plugin_decisions_scopes] }
- { deltaId: no-scenario-label, fold, spec-id: core_plugin_lapi_usage-metrics, confidence: high, candidates: [core_plugin_lapi_usage-metrics, core_plugin_decisionstore_store] }

Live catalog: remaining pack/intern and no-`scenario`-label promises. No cleanup/absence skip. No new intern-table spec leaf.
