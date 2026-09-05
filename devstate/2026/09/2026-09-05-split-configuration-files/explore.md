# Explore
IssueKey: 2026-09-05-split-configuration-files

## Concepts

**Config DTO**:
`configuration.Config` is the Traefik mapstructure/JSON bag. `CreateConfig` in `plugin.go` returns `configuration.New()`. Yaegi never evals a type named `Config`; it uses the pointer `CreateConfig` returns (`knowledge/research/ext_traefik_plugins_yaegi-constructor/notes.md`).

**File secret**:
`GetVariable` reads `keyFile` then inlined `key` via reflect. Used by validate, `Prepare`, captcha, redis password. Stays in `pkg/configuration`.

**Template compile**:
`GetTemplate` / `getContentTypeFromPath` compile ban/captcha files. Callers: `pkg/bouncer`, `pkg/captcha`, validate. Stays in `pkg/configuration`.

**Runtime TLS builder**:
`GetTLSConfigCrowdsec` / `getTLSConfig` build `*tls.Config` for LAPI and AppSec HTTP clients. Only production call site: `crowdsecconnection.New` (attach to `http.Client.Transport.TLSClientConfig`). Not a Traefik DTO job.

**PEM validate (not the builder)**:
`validateParamsTLS` parses a custom LAPI CA at config-check time. That stays with validation.

```
  dest master today
  pkg/configuration/configuration.go
  ┌──────────────┬──────────┬──────────┬──────────┬─────────────┐
  │ Config + New │ enums    │ secrets  │ template │ Validate*   │
  │              │          │          │          │ + TLS build │
  └──────────────┴──────────┴──────────┴──────────┴─────────────┘
                         TLS build used only by
                         crowdsecconnection.New → http.Client

  after this change
  pkg/configuration/
    config.go      Config, New, enums, EffectiveFailureAction
    secrets.go     GetVariable
    template.go    GetTemplate, getContentTypeFromPath
    validate.go    ValidateParams and helpers (incl. validateParamsTLS)
  pkg/crowdsecconnection/
    connection.go  New still builds http.Client
    tls.go         getTLSConfig / getTLSConfigCrowdsec (unexported)
```

## Decisions

- Split inside `pkg/configuration` only. Do not move `Config`, `CreateConfig`, JSON tags, or validation rules.
- Delete `configuration.go` after the split so the package has no leftover mixed file. Tests stay in `configuration_test.go` except TLS tests that follow the moved symbols.
- Enums stay in `config.go` next to `Config` (they are the DTO’s closed vocabulary). Do not add `mode.go`; the ticket listed that as an example, not a SHALL.
- Move `GetTLSConfigCrowdsec` and `getTLSConfig` into `pkg/crowdsecconnection/tls.go`. Unexport both; the only caller is the same package’s `New`.
- `New` keeps the same `http.Client` construction in `connection.go`. Do not file-split stream/appsec/live (sibling).
- `Prepare` stays as-is (CAPI host mutation is a sibling). TLS code already calls `configuration.GetVariable`; after the move it still does. No circular import: crowdsecconnection already imports configuration.
- Move `Test_GetTLSConfigCrowdsec` and `validPEM` into `pkg/crowdsecconnection` (same-package tests of the unexported builder). Leave remaining tests in `configuration_test.go`.
- `validateParamsTLS` stays in `validate.go`.
- No new Traefik research: CreateConfig already documented; file split in `pkg/configuration` does not move constructors.
- Spec: FindSpecHost at propose. Assumed **new** leaf under `core` / `plugin` for TLS-builder owner + file owners; middleware spec already covers CreateConfig on the root package (fold a one-line “unchanged” only if FindSpecHost says small adjustment — expected **new** because TLS owner is not in any live spec).
- Usage packets that name `pkg/configuration/configuration.go` as a Key file get a path update at devdocs-impact (`core_plugin_ip.md`, `core_plugin_decisionscope.md`). No new Language this phase.

## Open questions

- Q: Exact sibling file names (`config.go` vs keeping `configuration.go`)?
  Decision: assumed — `config.go` (DTO + `New` + existing enums), `secrets.go`, `template.go`, `validate.go`. Remove `configuration.go` after the split so one mixed file does not remain.
  By: explore

- Q: `mode.go` or constants file for enums?
  Decision: assumed — keep the existing const block in `config.go`. A `mode.go` would mis-name log/captcha/failure/scheme constants. Ticket’s names were examples.
  By: explore

- Q: Does `GetTLSConfigCrowdsec` stay exported after the move?
  Decision: assumed — no. Only `crowdsecconnection.New` calls it. Unexport as `getTLSConfigCrowdsec` in `pkg/crowdsecconnection`. Tests in that package can still call it.
  By: explore

- Q: Do TLS tests stay in `configuration_test.go`?
  Decision: assumed — no. Move `Test_GetTLSConfigCrowdsec` and shared `validPEM` with the symbols. Other tests stay in `configuration_test.go`.
  By: explore

- Q: Should HTTP client construction move into `tls.go` as well?
  Decision: assumed — no. Ticket says move the TLS builder next to client construction, not extract the clients. Sibling `2026-09-05-split-connection-files` owns connection.go splits.
  By: explore

- Q: Does `validateParamsTLS` move with the runtime builder?
  Decision: assumed — no. It is config validation (PEM parse at ValidateParams). Runtime client TLS is `getTLSConfig`.
  By: explore

- Q: Who owns client address / Host / trust hop for this change?
  Decision: resolved — none of this ticket’s files set or reconstruct identity. `pkg/ip` and connection identity stay owners elsewhere.
  By: explore

- Q: Which spec leaf hosts the file-owner and TLS-builder requirements?
  Decision: resolved — **new** `core_plugin_config_file-owners` (FindSpecHost at propose: not a small adjustment to `core_plugin_middleware_instance-reclaim`; candidates: that leaf and `core_plugin_config_file-owners`; confidence medium).
  By: propose
