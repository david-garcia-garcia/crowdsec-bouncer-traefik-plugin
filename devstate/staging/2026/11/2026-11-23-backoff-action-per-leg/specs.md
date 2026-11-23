# Specs
change: add-backoff-action-and-lapi-live-gate
- added core_plugin_lapi_admission-gate (new: the LAPI live/none admission gate; low-confidence fold into core_plugin_lapi_connection rejected, three requirement areas)
- modified core_plugin_lapi_failure-action (fold: ADDED backoff action and its header label)
- modified core_plugin_lapi_reclaim-key (fold: MODIFIED ownership key adds the live/none period)
- modified core_plugin_lapi_query-round-trip (fold: MODIFIED status error carries the code)
- modified core_plugin_appsec_client (fold: gate requirement REMOVED and split into four ADDED, default 10)
- modified core_plugin_appsec_failure-action (fold: fallback and unhealthy-skip requirements REMOVED and re-ADDED, default passthrough, backoff action)
- modified core_plugin_modsecurity_client (fold: gate requirement REMOVED and split into two ADDED, default 10)
- modified core_plugin_modsecurity_inspect (fold: gate-skip requirement REMOVED, two ADDED)
- modified core_plugin_middleware_bouncer (fold: MODIFIED header vocabulary and bypassCaptcha sources; three ADDED)
- modified core_plugin_middleware_config-validation (fold: WAF periods requirement REMOVED; three ADDED)
- modified build_e2e_pester_crowdsec-stack (fold: two MODIFIED; one ADDED LAPI live gate suite)
