# Devdocs impact
change: lapi-remediation-fallback

Pin: fixedPoint `origin/master`, head `3ef90d4e`, 49 reviewable paths.

## Units
- Remediation fallback — pattern — `pkg/lapi/client_decisions.go` `ingestRemediationKind` / `deletedTypeClearsStore`; spec `core_plugin_lapi_remediation-fallback`
- Stream apply — subsystem — `pkg/lapi/client_stream.go` `fetchAndApplyStreamDecisions`
- OriginBasedDecisionRemap (live strongest pick) — subsystem — `pkg/lapi/client_decisions.go` `strongestLiveDecision`; spec `core_plugin_lapi_origin-based-decision-remap`
- LAPI reclaim key — subsystem — `pkg/lapi/identity.go`, `pkg/lapi/session.go`; spec `core_plugin_lapi_reclaim-key`
- Config validation — subsystem — `pkg/configuration/configuration.go` `validateParamsRequired` (`lapiRemediationFallback` enum)

## Findings
- [x] wrong-fold  Remediation fallback — no packet (`core_plugin_lapi_remediation-fallback`); its Language term and knob gotchas were folded into `core_plugin_lapi_stream-apply`, which is stream-only, and the live leg sat in the `core_plugin_lapi_origin-based-decision-remap` Overview
  Produced: new `knowledge/devdocs/core_plugin_lapi_remediation-fallback.md` (Language term moved from stream-apply, created this run; How to use, snippet, Key files, Gotchas incl. the whitelist/allow position); row in `index_core_plugin.md`; stream-apply keeps stream usage plus a pointer and the short whitelist/allow line; origin-remap pointer retargeted.
- [x] stale-usage  Config validation — `core_plugin_middleware_config-validation` had no line for the `LapiRemediationFallback` enum, and its captcha-instance rule for failure actions reads as if it applied to the new `captcha` value
  Produced: one How-to bullet (accepted values, error text, captcha needs no instance).

Stream apply, OriginBasedDecisionRemap, and LAPI reclaim key: none (implement already updated them; checked against the code at head).
