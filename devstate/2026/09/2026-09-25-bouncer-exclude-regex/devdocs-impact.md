# Devdocs impact
change: bouncer-exclude-regex

## Units
- Bouncer — subsystem — `pkg/bouncer/bouncer.go` / `core_plugin_middleware_bouncer`
- Config validation — subsystem — `pkg/configuration/configuration.go` `ValidateParams` / `CompileExcludeRegex` / `core_plugin_middleware_config-validation`
- Forced decision header — subsystem — ServeHTTP order after forced `b` / `core_plugin_middleware_forced-decision`

## Findings
- [x] language-gap  Bouncer — `core_plugin_middleware` has How-to for exclude regexes, no Language term for Exclude match string
- [x] stale-usage  Forced decision header — `core_plugin_middleware_forced-decision` says header `c` still looks up; LAPI exclude now skips lookup before `passOrForcedCaptcha`
