# Devdocs impact
change: align-lapi-usage-metrics

## Units
- LAPI usage-metrics — subsystem — `pkg/crowdsecconnection/connection_metrics.go`
- Decision scopes — subsystem — `pkg/decisionscope/` (cache values may carry origin)
- Trusted-IP lookup — subsystem — `pkg/ip/network.go` (`Family`, `FamilyOfHostOrCIDR`)

## Findings
- [x] missing-packet  LAPI usage-metrics — no packet; produced `core_plugin_lapi_usage-metrics.md`
- [x] stale-usage  Decision scopes — Lookup now returns origin; cache suffix gotcha; updated `core_plugin_decisionscope.md`
- none remaining
