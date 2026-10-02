# Devdocs impact
change: intern-decision-scenario
fixedPoint: origin/master
head: e1934062b9cf5ecbac9e2c01985133d3ffdfa457

## Units
- DecisionStore — subsystem — `pkg/decisionstore` / spec `core_plugin_decisionstore_store` / `knowledge/devdocs/core_plugin_decisionstore.md`
- LAPI usage-metrics — subsystem — spec `core_plugin_lapi_usage-metrics` / `knowledge/devdocs/core_plugin_lapi_usage-metrics.md`
- Stream apply — subsystem — `pkg/lapi/client_stream.go` `pkg/lapi/client_decisions.go` / `knowledge/devdocs/core_plugin_lapi_stream-apply.md`

## Findings
- [x] stale-usage  DecisionStore — `core_plugin_decisionstore` How-to omitted `Decision.Scenario` on Put (stream `streamPutItem` / live `memoLive`); Key files omitted `pack.go` and `decision.go`
- [x] stale-usage  Stream apply — `core_plugin_lapi_stream-apply` How-to omitted copying LAPI `item.Scenario` and keeping Range/Redis on `KindOriginString` with no packed intern id

Language already on `core_plugin_decisionstore` (Scenario intern, Packed word 2+12+2+16) and `core_plugin_lapi_usage-metrics` (no `scenario` item label; reporter owns neither intern table). No missing-packet. No wrong-fold. usage-metrics usage enough.
