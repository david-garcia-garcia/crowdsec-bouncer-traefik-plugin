# Devdocs impact
change: one-lapi-open

## Units
- LAPI connection — subsystem — `pkg/lapi/` / spec `core_plugin_lapi_connection`
- Middleware New — subsystem — `plugin.go`
- LAPI reclaim key — subsystem — `pkg/lapi/session.go` OwnershipKey
- DecisionStore — subsystem — `pkg/decisionstore` / spec `core_plugin_decisionstore_store`
- Test log sink — pattern — `std_go_test_log-sink`

## Findings
- [x] stale-usage  LAPI connection — `core_plugin_lapi_connection` How-to and Overview still name `OpenStream` / `OpenLive`
- [x] stale-usage  Middleware New — `core_plugin_middleware` How-to still branches mode for LAPI Open; snippet uses `OpenStream`
- [x] stale-usage  LAPI reclaim key — `core_plugin_lapi_reclaim-key` How-to and snippet still name `OpenStream` / `OpenLive`
- [x] stale-usage  DecisionStore — `core_plugin_decisionstore` Overview and How-to still name `OpenStream` / `OpenLive`
- [x] stale-usage  Test log sink — `std_go_test_log-sink` snippet and gotcha still name `OpenStream`
