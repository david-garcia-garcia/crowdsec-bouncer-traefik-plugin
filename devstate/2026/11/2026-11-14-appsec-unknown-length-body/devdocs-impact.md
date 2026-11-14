# Devdocs impact
change: appsec-inspect-unknown-length-body

Pinned apply: `origin/master...eb320ee4` (42 reviewable paths). Unattended.

## Units
- AppSec Client body copy — subsystem — `pkg/appsec/query.go` (`newAppsecBodyRequest`, `copyClientBodyForAppsecAndRestoreForOrigin`, `hasBodyForAppsec`); spec `core_plugin_appsec_client`
- Body read timeout — pattern — `pkg/appsec/query.go` (`armBodyReadDeadline`, `cutClientBodyRead`, `bodyReadDeadlineFired`, `ErrBodyReadTimeout`), `pkg/bouncer/bouncer.go` (`applyAppsecServeHTTP`); spec `core_plugin_appsec_body-read-timeout`
- AppSec failure action — pattern — `pkg/bouncer/bouncer.go` (`applyAppsecServeHTTP`); spec `core_plugin_appsec_failure-action`
- Usage-metrics origin — subsystem — `pkg/lapi/client_metrics.go` (`OriginPluginAppsecBodyTimeout`); spec `core_plugin_lapi_usage-metrics`
- Remediation header reason — pattern — `pkg/bouncer/remediation_header.go` (`headerReasonAppsecBodyTimeout`); spec `core_plugin_middleware_bouncer`
- Inbound request (AppSec `Query` call site) — pattern — `pkg/bouncer/bouncer.go:459`
- Config catalog (`appsecBodyReadTimeoutSeconds`, non-positive `appsecBodyLimit`) — pattern — `pkg/configuration/configuration.go`
- Action rules (`bypassAppsec` as the streaming escape hatch) — pattern — README only; no code change in `pkg/httprule` or rule folding

## Findings
- [x] stale-usage  AppSec Client body copy — `core_plugin_appsec` How-to/Gotchas still described `isBodyUnreadable`, the `isMethodWithBody` drop set, "`appsecBodyLimit` `0` is unlimited", and a "readable body" gate; reclaim key lacked `appsecBodyReadTimeoutSeconds`; snippet used the old two-argument `Query`
- [x] language-gap  Body read timeout — `core_plugin_appsec` had no term for `ErrBodyReadTimeout` or for a body of unknown length; added **Body of unknown length** and **Body read timeout** (`_Avoid_` unreadable body / FailureAction ban), and dropped "readable" from **Client disconnected** and **AppSec Client**
- [x] stale-usage  AppSec failure action — `core_plugin_appsec` listed "an unreadable HTTP/2 or HTTP/3 body on POST, PUT, or PATCH" under `bouncerAppsecFailureAction`; now says a body read timeout is its own ban whatever the action
- [x] stale-usage  Usage-metrics origin — `core_plugin_lapi_usage-metrics` Language and How-to enumerated plugin drop origins without `plugin:appsec_body_timeout`
- [x] stale-usage  Inbound request — `core_plugin_clientrequest_inbound-request` snippet called `appsecClient.Query(req, pol)`; now passes `http.NewResponseController(rw)`
- none  Remediation header reason — `core_plugin_middleware_ban-page` already says each ban site passes its own `headerReason`; its reason list is illustrative. The new reason is documented in `core_plugin_appsec`.
- none  Config catalog — `core_plugin_middleware_config-validation` `requiredInt1` bullet is about the three HTTP timeouts and stays true; no packet claimed `appsecBodyLimit < 0` is invalid. Key validation lives in spec `core_plugin_appsec_body-read-timeout`.
- none  Action rules — `core_plugin_middleware_action-rules` already documents `bypassAppsec`; behaviour unchanged.

## Other edits this phase
- `README.md` § "Let streaming request bodies through (gRPC, Connect, long uploads)": read gate names POST/PUT/PATCH/DELETE; states that leaving out `Content-Length` does not skip inspection; remediation header only when `bouncerRemediationHeadersCustomName` is set; WARN is debounced (5 s); upgrade note for operators who used `passthrough` to let streams through (old code: failure action on POST/PUT/PATCH, uninspected with `passthrough` or on DELETE); "blocked when the body stays open past the timeout"; requests with `Content-Length` not affected; keep `appsecBodyReadTimeoutSeconds` below Traefik's entrypoint `readTimeout`. Variables entry says "remediation header".
- `pkg/appsec/query.go:59`, `:106`: comments no longer say "readable" (deferred here by `codereview_standards.md` finding 2).
