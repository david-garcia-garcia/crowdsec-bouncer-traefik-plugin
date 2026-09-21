# Devdocs impact
change: cursor-only-reclaim-key
pin: origin/master...HEAD (a57c8485a7ef8af3ec1eee986dd45ddff4cc926c...aca2eb54ef9a5fd646ebf4b5118d5bc3467d04d4) excluding `devstate/` and `.cursor/`

## Units
- LAPI reclaim key — subsystem — `pkg/lapi/session.go`, `pkg/lapi/identity.go` / spec `core_plugin_lapi_reclaim-key`
- LAPI live-router scope union — subsystem — `pkg/lapi/liveheaderscopes.go` / spec `core_plugin_lapi_scope-union`
- DecisionStore cache — subsystem — `pkg/lapi/decisionstore.go` / spec `core_cache_client_decision-store`
- Decision scopes — subsystem — `pkg/decisionscope` / spec `core_plugin_decisions_scopes`
- Reclaim context lease — pattern — `pkg/reclaim` / spec `std_go_reclaim_context-lease`
- Middleware New — subsystem — `plugin.go` / `knowledge/devdocs/core_plugin_middleware.md`
- LAPI connection — subsystem — `pkg/lapi/client_http.go` / `knowledge/devdocs/core_plugin_lapi_connection.md`
- Real-stack e2e — subsystem — `knowledge/devdocs/build_e2e_real.md`

## Findings
- [x] stale-usage  Middleware New — Language and Gotchas still name PeekLivePrefix, first-wins settings hash, and IdentityHex as the live Open key
- [x] stale-usage  LAPI connection — Gotchas still first-wins via PeekLivePrefix; How-to still names a live joiner `ignored`
- [x] stale-usage  Decision scopes — How-to still passes `lapiScopeHeaders` into the Client as stream `scopes=`
- [x] stale-usage  Real-stack e2e — usage-metrics gotcha still names warn-and-wire first-wins
- [x] language-gap  LAPI live-router scope union — `core_plugin_lapi_scope-union` has How-to, no Language term
