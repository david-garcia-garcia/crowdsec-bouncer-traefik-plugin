# Devdocs impact
change: 2026-09-20-lapi-session-subscribe

## Units
- LAPI reclaim key — subsystem — `knowledge/devdocs/core_plugin_lapi_reclaim-key.md`
- DecisionStore — subsystem — `knowledge/devdocs/core_plugin_decisionstore.md`
- Middleware New — subsystem — `knowledge/devdocs/core_plugin_middleware.md`
- LAPI connection — subsystem — `knowledge/devdocs/core_plugin_lapi_connection.md`

## Findings
- [x] stale-usage  LAPI reclaim key — How-to still said holder middleware names; slog is `middlewareNames`; `StoreKey` helper and `liveholders.go` are gone
- [x] stale-usage  DecisionStore — How-to still named deleted `OpenDecisionStore`; `StoreKey` helper is gone (`newChildStore` only)
