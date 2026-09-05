## Context

See `proposal.md` Why. Dest `master` keeps DTO, secrets, templates, validation, and runtime TLS in `pkg/configuration/configuration.go`. `crowdsecconnection.New` is the only production caller of `GetTLSConfigCrowdsec`; it then sets `http.Client` `TLSClientConfig`. `plugin.go` `CreateConfig` already returns `configuration.New()`. Yaegi requires those constructors on the module root (`knowledge/research/ext_traefik_plugins_yaegi-constructor/notes.md`).

FindSpecHost: **new** `core_plugin_config_file-owners` (not a small adjustment to `core_plugin_middleware_instance-reclaim`; that leaf is reclaim/`New`. Candidates: `core_plugin_middleware_instance-reclaim`, `core_plugin_config_file-owners`). Confidence medium.

## Goals / Non-Goals

**Goals:**
- One file per configuration job in `pkg/configuration`.
- Runtime TLS builder in `pkg/crowdsecconnection` next to HTTP client construction.
- Same tests, same operator YAML, same TLS outcomes.

**Non-Goals:**
- Splitting `connection.go` stream/appsec/live.
- Changing `Prepare` CAPI host mutation.
- Changing validation rules or JSON tags.
- Extracting `http.Client` construction into `tls.go`.

## Decisions

1. **Files:** `config.go` (Config, `New`, existing enums, `EffectiveFailureAction`), `secrets.go` (`GetVariable`), `template.go` (`GetTemplate`, `getContentTypeFromPath`), `validate.go` (`ValidateParams` and helpers including `validateParamsTLS`). Delete `configuration.go` after the move.
   Alternative: keep `configuration.go` as the DTO file — rejected; the mixed name would remain.
   Alternative: `mode.go` for enums — rejected; enums are Config vocabulary (log/captcha/scheme/failure), not only mode.

2. **TLS lives in `pkg/crowdsecconnection/tls.go`, unexported.** Same package as `New`, so no exported wrapper. Tests move with it (`Test_GetTLSConfigCrowdsec`, `validPEM`).
   Alternative: keep exported `configuration.GetTLSConfigCrowdsec` as a facade — rejected; circular import if it called crowdsecconnection, and it would leave the builder in the config package.

3. **`validateParamsTLS` stays in validate.go.** It is PEM check at ValidateParams, not client construction.

4. **`Prepare` unchanged.** TLS already reads secrets via `GetVariable`; after the move it still does.

## Risks / Trade-offs

- [Callers outside crowdsecconnection used GetTLSConfigCrowdsec] → Grep shows only `connection.go` and `configuration_test.go`. Unexport is safe.
- [Yaegi breaks if Config moves packages] → Config stays in `pkg/configuration`; only files split.
- [TLS tests fail after unexport] → Same-package tests in crowdsecconnection call the unexported names.

## Migration Plan

No operator config change. Rollback is revert.

## Open Questions

None. Deferrable unknowns live on `devstate/explore.md`.
