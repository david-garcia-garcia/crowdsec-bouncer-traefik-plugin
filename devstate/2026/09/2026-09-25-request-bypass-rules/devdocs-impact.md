# Devdocs impact
change: request-bypass-rules

## Units
- HTTP request rules — subsystem — `pkg/httprule` (`rule.go`, `set.go`)
- Middleware New — subsystem — `pkg/bouncer/bouncer.go` ServeHTTP skip sites + Config lists + `core_plugin_middleware`
- Config validation — subsystem — `ValidateParams` `httprule.New` wrap + `core_plugin_middleware_config-validation`
- Forced decision header — subsystem — `core_plugin_middleware_forced-decision`

## Findings
- [x] missing-packet  HTTP request rules — no packet; only How-to bullets on `core_plugin_middleware` and `core_plugin_middleware_config-validation`
- [x] stale-usage  Middleware New — `core_plugin_middleware` unused-keys gotcha omitted leftover exclude YAML; How-to did not point at the matcher packet
