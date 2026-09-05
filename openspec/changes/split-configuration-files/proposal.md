## Why

On `master`, `pkg/configuration/configuration.go` mixes the Traefik Config DTO, file secrets, template compile, validation, and runtime LAPI/AppSec TLS construction. Later edits keep touching five jobs, and the TLS builder sits in the config bag instead of next to the HTTP clients that use it.

## What Changes

- Split `pkg/configuration` into sibling files in the same package: DTO/`New`/enums, secrets, templates, validation.
- Move runtime `tls.Config` construction into `pkg/crowdsecconnection` next to LAPI/AppSec `http.Client` setup.
- Tests follow the moved symbols. Validation rules, Config JSON tags, and `CreateConfig` stay.
- Not **BREAKING**. Operator YAML and runtime TLS behaviour stay.

## Capabilities

### New Capabilities

- `core_plugin_config_file-owners`: Config DTO, secrets, templates, and validation live in `pkg/configuration`; runtime LAPI/AppSec TLS construction lives in `pkg/crowdsecconnection` next to those HTTP clients.

### Modified Capabilities

None.

## Impact

- `pkg/configuration/configuration.go` replaced by sibling files; TLS functions leave the package.
- `pkg/crowdsecconnection` gains the TLS builder; `New` call sites stay in that package.
- `pkg/configuration/configuration_test.go` keeps non-TLS tests; TLS tests move with the builder.
- `plugin.go` `CreateConfig` unchanged.
- Usage packets that name `configuration.go` as a Key file (`knowledge/devdocs/core_plugin_ip.md`, `knowledge/devdocs/core_plugin_decisionscope.md`).
