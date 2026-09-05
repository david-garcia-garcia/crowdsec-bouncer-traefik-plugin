# Split configuration.go into sibling files

Physical isolation: configuration.go (500+ lines) mixes five jobs. Desired: DTO stays the public Traefik shape; secrets, templates, validation live in sibling files in the same package; runtime TLS builder leaves the config bag and sits next to LAPI/AppSec HTTP construction. Behavior unchanged. Tests in configuration_test.go follow the moved symbols.

## Bound the ask (this ticket only)

`pkg/configuration/configuration.go` is the Traefik DTO plus file secrets, template compile, validation, AND runtime TLS. Split files inside the same package, for example:

- config.go (DTO + New defaults)
- mode.go or constants with the existing enums
- secrets.go (GetVariable)
- validate.go
- template.go (GetTemplate)

Move `GetTLSConfigCrowdsec` / `getTLSConfig` next to HTTP client construction in `pkg/crowdsecconnection` (that is in scope for this ticket). Do not change validation rules, public Config JSON tags, or plugin CreateConfig. Do not file-split crowdsecconnection’s stream/appsec/live (sibling). Do not change Prepare mutation of CAPI host (sibling 2026-09-05-config-prepare-snapshot) except as required to keep TLS construction compiling after the move.

Sibling tickets that MUST NOT be taken: 2026-09-05-split-connection-files, 2026-09-05-split-ip-trust, 2026-09-05-scope-headers-identity, 2026-09-05-remediation-codes-owner, 2026-09-05-decisionscope-mode-bool, 2026-09-05-config-prepare-snapshot.
