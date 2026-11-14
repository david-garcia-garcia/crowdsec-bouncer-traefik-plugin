## Why

`newAppsecBodyRequest` (`pkg/appsec/query.go`) classifies any HTTP/2 or HTTP/3 body without `Content-Length` as "unreadable" without trying to read it. With the default `bouncerAppsecFailureAction: ban` it drops POST, PUT, and PATCH with a 403 and never asks AppSec (upstream issue https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/405: `restic init` against `rest-server` sends an empty HTTP/2 POST without `Content-Length`). With `passthrough` the same body reaches origin uninspected, and an HTTP/2/3 DELETE without `Content-Length` is never inspected at all, so a client that strips an optional header gets less WAF inspection. One failure action also mixes "AppSec failed" with "the client sent no length", so operators cannot let restic through without failing open when AppSec is down.

## What Changes

- A POST, PUT, PATCH, or DELETE body without `Content-Length` (HTTP/1.1 chunked, HTTP/2 or HTTP/3) is read and inspected like any other body, capped at `appsecBodyLimit`, within a **total** read deadline.
- New public key `appsecBodyReadTimeoutSeconds` (default `30`, `< 1` rejected, no "disabled" value). It is part of the AppSec reclaim identity.
- Deadline expiry blocks the request whatever `bouncerAppsecFailureAction` says (fail-closed): ban response (`bouncerRemediationStatusCode`, ban template), remediation header `ban:appsec-body-timeout`, usage-metrics origin `plugin:appsec_body_timeout`, debounced WARN that tells the operator to exclude streaming routes with `bypassAppsec`. Not HTTP 408.
- **BREAKING**: the "unreadable body" class is removed. `bouncerAppsecFailureAction` again means only "AppSec failed" (500, unexpected status, unreachable, response read error). No key is reintroduced that lets such a body pass uninspected (`crowdsecAppsecUnreadableBodyBlock` stays gone).
- **BREAKING**: `appsecBodyLimit <= 0` becomes 10485760 (10 MiB). `0` no longer means "unlimited"; a negative value is no longer a validation error.
- An HTTP/2/3 DELETE body without `Content-Length` is inspected like one with it.
- gRPC and Connect get no Content-Type special case. Unary calls end and are inspected; client and bidirectional streams hit the deadline and are blocked. README documents how to exclude streaming routes with `bouncerActionRules` + `bypassAppsec`, with YAML examples and the trade-off.
- Unchanged: bodies larger than `appsecBodyLimit` (first N bytes inspected, remainder forwarded uninspected); GET/HEAD bodies (never read); bodies with a declared `Content-Length` (no plugin deadline).

## Capabilities

### New Capabilities

- `core_plugin_appsec_body-read-timeout`: the `appsecBodyReadTimeoutSeconds` key, the total read deadline on bodies of unknown length, the fail-closed block independent of the failure action, how the bouncer serves it (ban, header reason, metrics origin, captcha-rule precedence), and its WARN.

### Modified Capabilities

- `core_plugin_appsec_failure-action`: the failure action no longer covers a client request body; "One action covers 500, unreachable, and unreadable body" is removed and its other clauses move unchanged to the added "One action covers AppSec 500, unexpected status, and unreachable" (the three unreadable-body scenarios are replaced by two inspection scenarios; OpenSpec refuses dropping scenarios in a MODIFIED block); the removed-bools requirement states `crowdsecAppsecUnreadableBodyBlock` has no replacement.
- `core_plugin_appsec_client`: body limit `<= 0` is the 10 MiB default (replaces "Zero body limit forwards the full body"); body forwarding no longer depends on `Content-Length` or HTTP version and loses the separate drop set (renamed "Client body forwards only on body-bearing methods"); reclaim identity adds `appsecBodyReadTimeoutSeconds`; a deadline expiry takes precedence over client-disconnect classification.
- `core_plugin_middleware_bouncer`: closed remediation-header vocabulary gains `ban:appsec-body-timeout`.
- `core_plugin_lapi_usage-metrics`: plugin origins gain `plugin:appsec_body_timeout`.

## Impact

- Code: `pkg/appsec/query.go` (`Client.Query` signature, `newAppsecBodyRequest`, removal of `isBodyUnreadable` / `isMethodWithBody`, new sentinel and deadline helper), `pkg/appsec/client.go` (`Prepare` normalizes the limit, `Client` stores the deadline), `pkg/appsec/session.go` (identity), `pkg/bouncer/bouncer.go` (`applyAppsecServeHTTP`), `pkg/bouncer/remediation_header.go`, `pkg/lapi/client_metrics.go`, `pkg/configuration/configuration.go`.
- Tests: `pkg/appsec/zzz_*_test.go` (43 `Query` call sites migrate; unreadable-body tests rewritten), `pkg/configuration` tests, `pkg/bouncer` tests, `pkg/yaegitest` run of the deadline path, mock e2e `tests/e2e/mock/scenarios/appsec/{run.sh,dynamic.yml}`.
- Docs: `README.md` (new key, `appsecBodyLimit` semantics and upgrade note, streaming-bodies section, remediation-header row, `Content-Length` note). Usage packet `knowledge/devdocs/core_plugin_appsec.md` is updated at devdocs impact.
- Operators: requests that were dropped with 403 (restic) now reach AppSec; `passthrough` no longer forwards bodies without `Content-Length` uninspected; streaming request bodies (gRPC client/bidi streaming, Connect streaming, long-lived uploads without `Content-Length`) are blocked after `appsecBodyReadTimeoutSeconds` unless excluded with `bypassAppsec`; `appsecBodyLimit: 0` now caps at 10 MiB.
- Deliberate reshape: `appsec.Client.Query` receives the per-request read-deadline handle from the bouncer (`devstate` deviations row, by explore).
