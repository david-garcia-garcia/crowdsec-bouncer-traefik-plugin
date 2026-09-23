# Specs
change: unsubscribed-captcha-ban-warn

Live catalog: remaining live behavior (unsubscribed captcha kind WARNs then bans). Not cleanup-only.

FindSpecHost search: `openspec/specs/map.md` family `core` / `plugin` / `middleware`; walked `openspec/specs/core_plugin_middleware_*/spec.md` plus `core_plugin_lapi_failure-action` and `core_plugin_appsec_failure-action`. Candidates: `core_plugin_middleware_bouncer` (owner of "Captcha verdict without a published client is a ban"), `core_plugin_middleware_captcha-routing`, `core_plugin_middleware_forced-decision`, `core_plugin_lapi_failure-action`, `core_plugin_appsec_failure-action`.

verdicts:
- fold core_plugin_middleware_bouncer — ADDED unsubscribed WARN; small adjustment (one requirement) to the existing unpublished-client ban leaf; confidence high
- skip core_plugin_middleware_captcha-routing — routing after a Valid client; this WARN is pre-routing
- skip core_plugin_middleware_forced-decision — forced `c` already reaches `handleRemediationServeHTTP`
- skip core_plugin_lapi_failure-action — failure-action `captcha` without an instance name stays illegal at ValidateParams
- skip core_plugin_appsec_failure-action — AppSec JSON `action: captcha` stays on `handleAppsecResponseServeHTTP`

counts: fold 1, new 0, skip 4
