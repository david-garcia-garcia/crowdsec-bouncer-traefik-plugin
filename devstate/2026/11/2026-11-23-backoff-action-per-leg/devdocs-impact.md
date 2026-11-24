# Devdocs impact
change: add-backoff-action-and-lapi-live-gate

Pin: `origin/master...4fcf9b9b` (67 reviewable paths). Mode: unattended (conductor-delegated).

## Units
- Backoff action — pattern — `pkg/bouncer/bouncer_backoff_action.go`; spec `core_plugin_middleware_bouncer`
- LAPI live admission gate — subsystem — `pkg/lapi/client.go`, `pkg/lapi/client_decisions.go`; spec `core_plugin_lapi_admission-gate`
- Per-leg action resolvers and backoff-period validation — subsystem — `pkg/configuration/configuration.go`; spec `core_plugin_middleware_config-validation`
- LAPI ownership key — subsystem — `pkg/lapi/identity.go`; spec `core_plugin_lapi_reclaim-key`
- LAPI query round trip (typed status error) — subsystem — `pkg/lapi/client_http.go`; spec `core_plugin_lapi_query-round-trip`
- AppSec gate skip and failure-action default — subsystem — `pkg/appsec/query.go`, `pkg/bouncer/bouncer_serve_appsec.go`; specs `core_plugin_appsec_client`, `core_plugin_appsec_failure-action`
- ModSec gate default and gate-skip answer — subsystem — `pkg/bouncer/bouncer_serve_modsec.go`; specs `core_plugin_modsecurity_client`, `core_plugin_modsecurity_inspect`
- Captcha gate entry for failure and backoff actions (`captchaUnlessBypassed`) — pattern — `pkg/bouncer/bouncer_serve_captcha.go`; spec `core_plugin_middleware_bouncer`
- Fail-closed metrics origins — pattern — `pkg/bouncer/remediation_header.go`, `pkg/lapi` origins; spec `core_plugin_middleware_bouncer`

## Findings
- [x] language-gap  Backoff action — `core_plugin_middleware.md` defines **Failure action** but has no **Backoff action** term, and that term's default sentence still says AppSec defaults to `ban` and that only "either WAF leg" skips
- [x] stale-usage  Backoff action — `core_plugin_middleware.md` How to use still says a gate skip on a WAF leg just continues; Bouncer field list, LAPI Client contents, ownership-key Gotcha, and per-router Gotcha omit the backoff actions, the LAPI live gate, and the stricter-than WARN
- [x] stale-usage  LAPI live admission gate — `core_plugin_lapi_connection.md` names `liveQueryHealthy` but not what counts as failure vs success, the admission-error path, the log lines, or that cache hits never consult the gate; `pkg/lapi/client_decisions.go` missing from Key files
- [x] stale-usage  LAPI live admission gate — `core_plugin_modsecurity_client.md` Language **Admission gate** says the gate sits "on a WAF Client" only
- [x] stale-usage  Captcha gate entry — `core_plugin_middleware_captcha-routing.md` caller list (header reason + downgrade reason) omits `captchaUnlessBypassed` (LAPI failure action and every backoff action)
- [x] stale-usage  Captcha gate entry — `core_plugin_middleware_action-rules.md` list of functions that ask `bypassesCaptcha` omits `captchaUnlessBypassed`
- [x] stale-usage  AppSec / ModSec gate skip — `core_plugin_wafhop_shared-request.md` unreadable-body rule says "apply the leg's own failure action" with no gate-skip branch
- [x] stale-usage  Fail-closed metrics origins — `core_plugin_lapi_usage-metrics.md` does not say a backoff `ban` / `captcha` counts under the leg's failure origin

Already current (no finding): `core_plugin_middleware_config-validation.md`, `core_plugin_lapi_reclaim-key.md`, `core_plugin_lapi_query-round-trip.md`, `core_plugin_appsec.md`, `core_plugin_modsecurity_inspect.md`, `build_e2e_real.md` (all updated in implement).

## Usage docs outside the catalog

Checked `docs/` (every page, including untouched `modes.md`, `middleware-architecture.md`, `connect-to-crowdsec.md`, `rate-limit.md`, `how-to/*`), `README.md`, `examples/`, `tests/e2e/**/README.md`, and e2e config/Pester comments for: AppSec failure action default `ban`, AppSec cooldown 30, ModSec gate off by default, "only the WAFs back off", "no failure action while skipping".

- No stale default left in `docs/`, `README.md`, or `examples/`. The `30` values left in `examples/modsecurity/dynamic.yml` and `docs/modsecurity.md` are explicit settings with matching comments, not stated defaults.
- [x] `tests/e2e/real/instance_severance.Tests.ps1` comment "Unbound legs answer with the default failure action (ban, 403)": an unbound AppSec leg now passes; the 403 comes from the unbound LAPI leg. Comment narrowed to LAPI; the assertion is unchanged.

## Review
Verdict: in progress
