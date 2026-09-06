# Explore
IssueKey: 2026-09-06-configuration-validateparams

## Concepts

ValidateParams runs at plugin startup (`plugin.go`) before any Prepare rewrites config. AppSec scheme fallback and key copy happen later in `appsec.Prepare`; validation must use the same **effective** scheme (`CrowdsecAppsecScheme` when non-empty, else `CrowdsecLapiScheme`) so URL format matches runtime.

`GetTLSConfigCrowdsec(..., true)` uses `CrowdsecAppsec` TLS fields only when `CrowdsecAppsecScheme != ""`; otherwise it reuses LAPI TLS prefix — validation should mirror that split.

Alone mode intentionally skips LAPI URL/key/TLS (CAPI rewrite in `lapi.Prepare`) but still initializes captcha (when failure action is captcha) and logging — those checks must not sit after the alone early return.

## Decisions

1. **AppSec URL** — use effective scheme helper inline; fix line 339 bug.
2. **AppSec TLS** — when `CrowdsecAppsecScheme` is set and HTTPS with verify enabled, parse `CrowdsecAppsecTLSCertificateAuthority` like LAPI CA today. When AppSec scheme empty, runtime uses LAPI TLS; no duplicate AppSec CA check (LAPI branch covers it for non-alone modes).
3. **Alone mode** — move captcha credential/template, ban template, and log checks to run for all modes; alone block only validates CAPI credentials then skips LAPI/AppSec connection block.
4. **Tests** — table-driven additions in `configuration_test.go` only; no pkg/captcha changes.
5. **Spec** — fold validation requirements into new delta under `core_plugin_middleware_config-validation` (configuration is middleware-owned, not lapi/appsec packages).

## Open questions

- Q: Whether AppSec client cert fields (`CrowdsecAppsecTLSCertificateBouncer*`) need startup parse in ValidateParams, or CA-only parity is enough?
  Decision: assumed — CA-only at ValidateParams matches LAPI today (`validateParamsTLS` parses CA PEM only; client cert pair errors surface at `GetTLSConfigCrowdsec` / `appsec.Open`). Do not add bouncer cert parse in this ticket.
  By: explore
