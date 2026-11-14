# Specs
change: lapi-remediation-fallback
- added core_plugin_lapi_remediation-fallback (FindSpecHost new, confidence medium; candidates: core_plugin_lapi_origin-based-decision-remap, core_plugin_lapi_failure-action, core_plugin_lapi_stream-apply, core_plugin_decisions_scopes, core_plugin_middleware_config-validation; new public knob with six requirements, past the fold threshold; failure-action is LAPI-unreachable, origin-remap is per-Bouncer apply)
- modified core_plugin_lapi_origin-based-decision-remap (FindSpecHost fold, high; "Origin remap is one hop at Bouncer apply", "Live strongest pick uses LAPI type": unknown type follows the fallback, sample `allow` → `throttle`)
- modified core_plugin_decisions_scopes (FindSpecHost fold, high; "Ban wins across scopes": unknown type follows the fallback)
- modified core_plugin_lapi_reclaim-key (FindSpecHost fold, high; "Stream session is LAPI URL plus bouncer key": knob in ownership key and, when not `ban`, SessionHex)
- not written: core_plugin_lapi_stream-apply, core_plugin_middleware_config-validation (no delta; the new leaf owns the Deleted rule and its enum validation)
