# Devdocs impact
change: split-configuration-files

## Units
- Plugin middleware New — subsystem — `knowledge/devdocs/core_plugin_middleware.md`
- Trusted-IP lookup — subsystem — `knowledge/devdocs/core_plugin_ip.md`
- Decision scopes — subsystem — `knowledge/devdocs/core_plugin_decisionscope.md`

## Findings
- [x] stale-usage  Plugin middleware New — Key files omitted `pkg/configuration/`; How-to did not say TLS construction lives in `pkg/crowdsecconnection`
- [x] stale-usage  Trusted-IP lookup — Key files named deleted `configuration.go`
- [x] stale-usage  Decision scopes — Key files named deleted `configuration.go`

Produced: `core_plugin_middleware.md`, `core_plugin_ip.md`, `core_plugin_decisionscope.md`. No new packet (file owners are how we use existing plugin Config, not a new unit).
