# Devdocs impact
change: put-decision-scope-headers-on-identity

## Units
- CrowdsecConnection reclaim identity — subsystem — `pkg/crowdsecconnection/identity.go`
- Header-mapped decisionScopeHeaders — pattern — `pkg/decisionscope/`, `core_plugin_decisionscope`
- Plugin middleware New — subsystem — `plugin.go`, `pkg/bouncer/bouncer.go`

## Findings
- [x] stale-usage  decisionScopeHeaders — `core_plugin_decisionscope.md` said pass into both types and avoid Country on the reclaim key; implement already put the map on identity and dropped the Bouncer copy
- [x] stale-usage  CrowdsecConnection / Bouncer Language — `core_plugin_middleware.md` identity field list omitted the map; implement already added it

Produced in implement (task 3.2). No further packet writes.
