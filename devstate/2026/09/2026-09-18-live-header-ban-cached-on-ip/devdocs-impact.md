# Devdocs impact
change: write-ip-query-result-to-ip-cache-key

## Units
- LAPI connection — subsystem — knowledge/devdocs/core_plugin_lapi_connection.md (`pkg/lapi/client_live.go`)
- Decision scopes — subsystem — knowledge/devdocs/core_plugin_decisionscope.md (spec `core_plugin_decisions_scopes`)
- Trusted-IP lookup — subsystem — knowledge/devdocs/core_plugin_ip.md
- DecisionStore cache — subsystem — knowledge/devdocs/core_cache_client.md

## Findings
- [x] stale-usage  Decision scopes — live How-to omits the IP-slot vs `HeaderScopeKey` write the apply added
- [x] stale-usage  LAPI connection — How-to/Gotchas omit that the IP-key TTL follows the IP query, not the merged header duration
