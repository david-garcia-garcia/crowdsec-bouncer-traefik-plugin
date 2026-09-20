# Devdocs impact
change: lapi-session-exclusive

## Units
- DecisionStore — subsystem — `pkg/decisionstore` / `core_plugin_decisionstore`
- Stream single-flight — pattern — `core_plugin_lapi_stream-single-flight`
- LAPI reclaim key — pattern — `core_plugin_lapi_reclaim-key`
- Reclaim context lease — pattern — `std_go_reclaim`
- Middleware New — subsystem — `core_plugin_middleware`
- GitHub Actions GOPATH — pattern — `build_ci_github`

## Findings
- [x] stale-usage  DecisionStore — `OpenDecisionStore` snippet omits `name`; Gotcha still says StoreKey includes Redis params
- [x] language-gap  CreatedBy — `core_plugin_decisionstore` has How-to `createdBy`, no Language term
- [x] stale-usage  LAPI reclaim key — StoreKey still documented with Redis params; Peek blanket-forbid; Redis host change still said to Open a different DecisionStore
- [x] stale-usage  Reclaim context lease — Overview still forbids exporting or calling exact `Peek`
- [x] language-gap  Peek — exact Peek is first-class in the apply; `std_go_reclaim` has no Language term
- [x] stale-usage  Middleware New — Gotcha still says do not call Peek; exclusive-name fail is missing
