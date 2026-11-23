# Devdocs impact
change: waf-inspect-unknown-length-body

Pin: `origin/master...3a89060c` (71 reviewable paths). Skipped as units: tests, e2e compose and Pester fixtures, `knowledge/research/` (research store, not devdocs), operator `docs/`. Removed unit with no production surface: the unreadable-body class (`IsBodyUnreadable`, `IsMethodWithBody`, `errUnreadableBody`); no packet for it, stale mentions dropped below.

## Units
- Body read deadline (shared WAF body read) — pattern — `pkg/wafhop/body.go` (`ReadBody`, `ErrBodyReadTimeout`, `cutBodyRead`); spec `core_plugin_wafhop_shared-request`
- WAF client-body answers — pattern — `pkg/bouncer/bouncer_serve_waf.go` (`handleBodyReadTimeoutServeHTTP`, `error:body-read-timeout`); spec `core_plugin_middleware_bouncer`
- AppSec Client (Query body path, identity, body limit) — subsystem — `pkg/appsec/query.go`, `client.go`, `session.go`; specs `core_plugin_appsec_client`, `core_plugin_appsec_failure-action`
- ModSec inspect — subsystem — `pkg/modsecurity/inspect.go`; spec `core_plugin_modsecurity_inspect`
- ModSec Client (ownership key) — subsystem — `pkg/modsecurity/session.go`; spec `core_plugin_modsecurity_client`
- Config validation (two read-timeout keys, `appsecBodyLimit`) — subsystem — `pkg/configuration/configuration.go`; spec `core_plugin_middleware_config-validation`

## Findings
- [x] language-gap  Body read deadline — `core_plugin_wafhop_shared-request` had the removed term "Unreadable body" and no term for the deadline
  Produced: "Unreadable body" replaced by **Body read deadline** (definition + `_Avoid_`).
- [x] stale-usage  Body read deadline — `core_plugin_wafhop_shared-request` How to use told legs to check `IsBodyUnreadable` and apply the failure action; `ReadBody(req, limit, mode)` signature; Gotcha "ReadBody treats 0 as no cap"
  Produced: How to use (no length check, `ReadBody(req, limit, mode, ctrl, timeout)`, three client-body sentinels before admission); Gotchas (non-positive limit is a caller bug, deadline classified before disconnect, success path never sets a deadline, concrete `*http.ResponseController` under Yaegi); Overview names the per-leg timeout keys; domain-index description in `index_core_plugin.md`.
- [x] stale-usage  WAF client-body answers — `core_plugin_wafhop_shared-request` listed only the disconnect and body-read handlers
  Produced: `handleBodyReadTimeoutServeHTTP` (400, `error:body-read-timeout`, debounced WARN per leg) in How to use.
- [x] stale-usage  AppSec Client — `core_plugin_appsec` failure-action list included an unreadable HTTP/2+ body; `appsecBodyLimit` `0` is unlimited; `Gate.BackingOff()` gate-skip of an unreadable body; Gotcha "Two method predicates … Do not collapse them"; client-body shapes; `Query(req, pol)` snippet; identity without `appsecBodyReadTimeoutSeconds`
  Produced: all corrected (one predicate `isMethodWithForwardableBody`; 10 MiB default via `EffectiveAppsecBodyLimit`; `ErrBodyReadTimeout` shape and switch order; `Query(req, pol, ctrl)` snippet; identity and ownership-key lists).
- [x] language-gap  AppSec Client — `core_plugin_appsec` had Client disconnected / Client body read error but no term for the deadline outcome
  Produced: **Body read timeout** term (`ErrBodyReadTimeout`).
- [x] stale-usage  ModSec inspect — `core_plugin_modsecurity_inspect` Language "WAF failure" included a streamed body; `Inspect(req, failureAction)`; unreadable-body rule with `Gate.BackingOff()`; snippet without the deadline case
  Produced: "WAF failure" no longer covers a client body; `Inspect(req, ctrl)`; body bullet reads every body under `modsecBodyReadTimeoutSeconds`; snippet and Gotcha add `wafhop.ErrBodyReadTimeout`.
- [x] stale-usage  ModSec Client — `core_plugin_modsecurity_client` ownership key lacked `modsecBodyReadTimeoutSeconds`
  Produced: Language and How to use name the new key.
- [x] stale-usage  Config validation — `core_plugin_middleware_config-validation` kept `AppsecBodyLimit` in `requiredInt0`; no mention of the two `requiredInt1` read-timeout keys
  Produced: both keys in `requiredInt1` (default 30); `AppsecBodyLimit` not range-checked, `<= 0` = 10 MiB.
- [x] stale-usage  AppSec / ModSec ownership keys — `core_plugin_middleware` constructor bullet listed the leg key knobs without the read timeouts
  Produced: both keys added.

## Notes
- `admission.Gate.BackingOff()` lost its last production caller in this diff (both callers were the removed drop paths). Not a devdocs finding; noted as `knowledge/debt/2026-11-23-admission-gate-backingoff-unused.md` (`issues.md`, note large) because the gate belongs to `2026-11-23-backoff-action-per-leg`.
