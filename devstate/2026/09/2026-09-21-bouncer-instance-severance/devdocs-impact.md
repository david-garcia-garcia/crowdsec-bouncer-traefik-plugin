# Devdocs impact
change: bouncer-instance-severance

## Units
- Middleware New — subsystem — `plugin.go`, `core_plugin_middleware.md`
- Config validation — subsystem — `pkg/configuration`, `core_plugin_middleware_config-validation.md`
- Named instance slot — pattern — `pkg/instance`, `core_plugin_middleware_named-instance` (spec)
- LAPI reclaim key — subsystem — `core_plugin_lapi_reclaim-key.md`
- DecisionStore — subsystem — `core_plugin_decisionstore.md`
- LAPI scope union — subsystem — `core_plugin_lapi_scope-union.md`
- Bouncer request path — subsystem — `pkg/bouncer` (folded in Middleware New)
- AppSec client — subsystem — `core_plugin_appsec.md`

## Findings
- [x] stale-usage  Middleware New — `core_plugin_middleware.md` duplicated pre-severance Language blocks (`Failure action`, `Prepared config`, `Bind context`, old `Two configuration axes` with `lapiMode: appsec`)
- [x] stale-usage  DecisionStore — `core_plugin_decisionstore.md` `CreatedBy` and OpenDecisionStore usage still named Traefik router `name` after instance-name exclusive Peek
- [x] stale-usage  LAPI reclaim key — `core_plugin_lapi_reclaim-key.md` DecisionStore Peek bullets still said Traefik `name` / many routers
- [x] stale-usage  LAPI scope union — `core_plugin_lapi_scope-union.md` Language and Overview still said every live constructor after opener-only registration

## Verdict
in progress
