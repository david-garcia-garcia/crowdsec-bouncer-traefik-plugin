# Specs
change: lapi-ban-retry-after
- modified core_plugin_middleware_bouncer (fold, high: ADDED "A LAPI ban answered 429 carries Retry-After"; MODIFIED "Live stream and alone lookup uses one Store entry")
- modified core_plugin_decisionstore_store (fold, high: ADDED "Store lookup returns the winning decision's time left"; MODIFIED "DecisionStore owns the origin intern table", "DecisionStore interns the raw LAPI scenario")
- modified core_plugin_decisions_scopes (fold, high: MODIFIED "Remediation values carry kind then origin", "Live IP cache slot is the IP query result")
- modified core_plugin_lapi_stream-apply (fold, high: MODIFIED "Stream apply writes deleted before new")
