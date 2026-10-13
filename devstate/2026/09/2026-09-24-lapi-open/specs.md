# Specs
change: one-lapi-open
- fold core_plugin_lapi_connection (high) — import `Open`; AdoptTransport after `Open` bind. Candidates: core_plugin_lapi_connection, core_plugin_lapi_reclaim-key, core_plugin_decisionstore_store
- fold core_plugin_decisionstore_store (high) — same Traefik `New` ctx as `lapi.Open`. Candidates: core_plugin_decisionstore_store, core_plugin_lapi_connection
