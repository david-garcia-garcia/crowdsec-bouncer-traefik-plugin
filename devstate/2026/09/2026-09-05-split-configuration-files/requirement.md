# Requirement
IssueKey: 2026-09-05-split-configuration-files

## Problem
`pkg/configuration/configuration.go` (600 lines) holds five jobs in one file: the Traefik Config DTO and defaults, mode/log/captcha/failure enums, file-secret resolution, ban/captcha template compile, validation, and runtime `tls.Config` construction for LAPI/AppSec HTTP. The TLS builder belongs next to the clients that use it, not in the config bag.

## Current (code)
- `pkg/configuration/configuration.go` defines package comment, enums (`AloneMode` … `FailureActionCaptcha`), `Config` with JSON tags, `New` defaults, `GetVariable` (reflect `key`/`keyFile`), `GetTemplate` plus `getContentTypeFromPath`, `ValidateParams` and helpers (`validateFailureAction`, `validateDecisionScopeHeaders`, `validateURL`, `validateParamsAPIKey`, `validateParamsTLS`, `validateParamsIPs`, `validateCaptcha`, `validateParamsRequired`, `contains`, `EffectiveFailureAction`), and `getTLSConfig` / `GetTLSConfigCrowdsec`.
- `plugin.go` `CreateConfig` returns `configuration.New()`; `New` calls `configuration.ValidateParams` then `crowdsecconnection.Prepare`.
- `pkg/crowdsecconnection/connection.go` `Prepare` resolves secrets via `GetVariable` and mutates CAPI host in AloneMode (sibling ticket). `New` calls `configuration.GetTLSConfigCrowdsec` then attaches the result to `http.Client` `TLSClientConfig` for LAPI and AppSec (lines ~200–274).
- `pkg/configuration/configuration_test.go` tests `contains`, `GetVariable`, `ValidateParams` / helpers, `GetTLSConfigCrowdsec`, `getContentTypeFromPath`, `validateDecisionScopeHeaders` in the configuration package.
- `pkg/captcha/captcha.go` and `pkg/bouncer/bouncer.go` call `configuration.GetTemplate` / `GetVariable`.
- Yaegi still requires root `CreateConfig` / `New` (`knowledge/research/ext_traefik_plugins_yaegi-constructor/notes.md`). Config type already lives in `pkg/configuration`; splitting files in that package does not move the constructor.

## Desired
- Same package: DTO + `New` in one file; enums in a sibling; `GetVariable` in secrets; `GetTemplate` in template; validation in validate. Public `Config` JSON tags, validation rules, and `CreateConfig` unchanged.
- Move `GetTLSConfigCrowdsec` / `getTLSConfig` into `pkg/crowdsecconnection` next to HTTP client construction. Call sites and tests follow the moved symbols. Behavior unchanged.
- Touch `Prepare` only as needed to keep TLS construction compiling after the move. Do not change CAPI host mutation.

## Affected
- `pkg/configuration/configuration.go` (split; TLS functions leave)
- `pkg/configuration/configuration_test.go` (tests follow moved symbols)
- `pkg/crowdsecconnection/connection.go` (TLS builder lives next to `http.Client` construction)
- Call sites of `GetTLSConfigCrowdsec` (today only `connection.go` `New`)
- Usage packets that name `pkg/configuration/configuration.go` as the single file (`knowledge/devdocs/core_plugin_ip.md`, `knowledge/devdocs/core_plugin_decisionscope.md`)

## Out of scope
- File-splitting crowdsecconnection stream/appsec/live (`2026-09-05-split-connection-files`).
- Changing `Prepare` CAPI host / interval mutation (`2026-09-05-config-prepare-snapshot`).
- Split IP trust, scope-headers identity, remediation-codes owner, decisionscope mode bool (named sibling tickets).
- Changing validation rules, `Config` JSON tags, or `plugin.go` `CreateConfig`.
- New config keys or TLS behavior (custom CA vs system pool vs insecure skip stays as today).

## Unknowns
- Exact sibling file names (`config.go` vs keeping `configuration.go` for the DTO).
- Whether `GetTLSConfigCrowdsec` stays that exported name after the move, or becomes an unexported builder used only inside crowdsecconnection.
- Whether TLS tests stay in `configuration_test.go` or move to `pkg/crowdsecconnection`.

## Tensions
- Ticket says “for example” file names; commandments want the file named for the type (`Config` → `config.go`) and one job per file.
- TLS tests currently live in `pkg/configuration`; after the move they cannot stay if the symbols leave the package, unless a thin wrapper remains (ticket says move the functions, tests follow).
- `Prepare` CAPI mutation is a sibling; this ticket may still import `GetVariable` from configuration after the TLS move.
