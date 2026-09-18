# Devdocs impact
change: pack-decision-origin

## Units
- Origin dictionary — subsystem — `pkg/lapi/origindict.go` / `core_cache_client_origin-dictionary`
- DecisionStore cache — subsystem — `pkg/lapi/decisionstore.go` / `pkg/cache` / `core_cache_client_decision-store`
- Decision scopes — subsystem — `pkg/decisionscope` / `core_plugin_decisions_scopes`
- LAPI usage-metrics — subsystem — `pkg/lapi/client_metrics.go` / `core_plugin_lapi_usage-metrics`

## Findings
- [x] missing-packet  Origin dictionary — no packet; only implied on DecisionStore cache
- [x] stale-usage  DecisionStore cache — memory How-to is TTL map only; no packed slots or intern table
- [x] stale-usage  Decision scopes — lookup snippet treats second return as origin; Range membership Language is string-suffix only
- [x] language-gap  LAPI usage-metrics — compact active-decision slots are first-class; packet has no Language term and still persists via `RemediationWithOrigin`
