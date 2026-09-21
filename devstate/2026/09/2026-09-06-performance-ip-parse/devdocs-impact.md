# Devdocs impact
change: parse-client-ip-once

## Units
- Trusted-IP lookup — subsystem — `knowledge/devdocs/core_plugin_ip.md`
- Decision scopes — subsystem — `knowledge/devdocs/core_plugin_decisionscope.md`
- LAPI usage-metrics — subsystem — `knowledge/devdocs/core_plugin_lapi_usage-metrics.md`

## Findings
- [x] stale-usage  Trusted-IP lookup — How-to still says call Contains / ContainsIP on the request path; ServeHTTP uses ContainsIP only
  Produced: request-path How-to now says ContainsIP; Contains remains for string callers.
