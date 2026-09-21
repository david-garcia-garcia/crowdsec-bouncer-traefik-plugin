# Devdocs impact
change: lapi-transport-router-policy

## Units
- Middleware New — subsystem — `pkg/bouncer` / `plugin.go` / `knowledge/devdocs/core_plugin_middleware.md`
- LAPI connection — subsystem — `pkg/lapi` / `openspec/changes/lapi-transport-router-policy/specs/core_plugin_lapi_connection`
- Failure action — pattern — `pkg/bouncer` / Language on `knowledge/devdocs/core_plugin_middleware.md`

## Findings
- [x] stale-usage  Middleware New — How-to omits LiveLookup TTL argument and last-write shared cache; Gotcha lifecycle INFO omits sessionKey + reason and joiner/transport INFO; LapiStreamStartupBlock write-once not stated
- [x] missing-packet  LAPI connection — no packet whose heading is this unit; only How-to bullets on `core_plugin_middleware.md`
