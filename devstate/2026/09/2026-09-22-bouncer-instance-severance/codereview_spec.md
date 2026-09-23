# Spec

1. [missing] openspec/changes/bouncer-instance-severance/specs/core_plugin_middleware_config-validation/spec.md — Requirement: ValidateParams test coverage for mode and helper gaps — configuration package SHALL include unit tests for instance name E2/E3 cases
   Status: skipped
   Argument: leftover-name ValidateParams coverage already exists; not adding a second E2/E3 file this pass.
2. [missing] openspec/changes/bouncer-instance-severance/specs/build_e2e_pester_crowdsec-stack/spec.md — Requirement: Instance severance real e2e suite — SHALL assert ordered `msg`, `instanceName`, and `incarnation` (and `traefikName` on bouncer lines); T2 THEN distinct remediation headers per route
   Status: skipped
   Argument: Traefik cancel-vs-grace races make ordered lifecycle log asserts flake; HTTP outcomes stay the e2e contract.
3. [extra] `pkg/configuration/configuration.go:140` — public `reclaimGraceSeconds` is not in the change config surface
   Status: skipped
   Argument: operator knob requested during implement so e2e can use 2s grace.
4. [extra] `pkg/instance/tables.go:220` — `ClearPublisher` immediately unbinds slots when a later `New` does not open that leg; not named; no `[x] taken` row
   Status: skipped
   Argument: required so a reconstructed New without that leg unbinds subscribers (R5).
5. [wrong] openspec/changes/bouncer-instance-severance/specs/core_plugin_middleware_instance-slots/spec.md — Requirement: Clear is generation-aware on grace Close — SHALL require recorded publisher match; `pkg/instance/tables.go:237` clears on dying pointer only
   Status: done
   Argument: spec now says the dying pointer is the generation.
