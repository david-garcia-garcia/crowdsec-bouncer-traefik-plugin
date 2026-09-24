# Devdocs impact
change: 2026-09-24-template-startup-warn

## Units
- Config validation — subsystem — `pkg/configuration` `ValidateParams`; `openspec/specs/core_plugin_middleware_config-validation`
- Captcha template owner — subsystem — `pkg/captcha` `Client.New`
- Ban template owner — subsystem — `pkg/bouncer` `New`
- TemplateUnavailableReason — pattern — `pkg/configuration` `TemplateUnavailableReason`

## Findings
- [x] stale-usage  Config validation — `core_plugin_middleware_config-validation` How-to and Gotchas still required empty/unloadable captcha paths and ban paths to fail `ValidateParams`, and `Client.New` to return `GetTemplate` errors

none beyond the row above.
