# Delivery

## Motivation

With AppSec enabled, the bouncer buffers readable POST, PUT, PATCH, and DELETE bodies before calling the AppSec listener. That path matches normal forwardable requests: known or positive `Content-Length`, body not classified as unreadable under HTTP/2 or HTTP/3 streaming rules.

If the client stops sending the body mid-copy (HTTP/2 stream cancel, request context canceled, truncated body versus `Content-Length`), `io.ReadAll` on the tee/limit reader fails. `newAppsecBodyRequest` wraps that as `appsecQuery:GetBody` and does not consult `crowdsecAppsecFailureAction`. `applyAppsecServeHTTP` treats any non-captcha `Query` error as an AppSec failure and responds with HTTP 403 and `ReasonAPPSEC`, even though AppSec never received the request. Operators who set `crowdsecAppsecFailureAction: passthrough` still hit this ban path; the failure is easy to miss at default log level because the message looks like a generic AppSec query error.

Upstream report: [maxlerebourg/crowdsec-bouncer-traefik-plugin#395](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/395).

Leaving it in place produces false AppSec bans on benign client disconnects, undermines the unified failure-action knob for a common edge case, and can block or confuse end users who already abandoned the request.

Priority: P2 — real operator and end-user pain on client disconnect, with `FailureAction` intended as the control but ineffective on this path today.

## Implementation

After `io.ReadAll` fails while buffering a forwardable body, read errors classified as client-gone (`context.Canceled`, `context.DeadlineExceeded`, `io.ErrUnexpectedEOF` via `errors.Is`) become `errClientBodyDropped`. `Query` maps that sentinel through the existing `resultForFailureAction` helper with message prefix `appsecQuery:clientBodyDropped`, the same family as unreachable, AppSec 500, and AppSec response-body I/O fallbacks. Unclassified read faults keep `appsecQuery:GetBody` wrapping so they still follow today’s ban wiring in `applyAppsecServeHTTP`.

`passthrough` returns allow without reaching AppSec. `ban` and `captcha` use the existing failure-action mapping without calling AppSec. No bouncer or new config key changes; regression coverage lives in `pkg/appsec/zzz_query_test.go` (table over the three client-gone errors plus an unclassified error that must stay on the `GetBody` path).

## What this changes
**Operators.** `crowdsecAppsecFailureAction` now governs client disconnect or cancel during AppSec body buffering; `passthrough` stops issuing false `ReasonAPPSEC` 403s on that path, and logs/errors distinguish `appsecQuery:clientBodyDropped` from unclassified `appsecQuery:GetBody` faults.
**Admin users.** None.
**Developers.** AppSec `Query` honors failure action for classified client-body-dropped reads; unclassified body read errors remain `appsecQuery:GetBody` and still surface as ban-path errors from `Query`.
**End users.** Mid-upload disconnect with operator `passthrough` no longer receives a false AppSec 403; with `ban`, the request is still forbidden but via the failure-action drop path rather than a spurious AppSec verdict.

## Stored data model
None.

## Findings
[P3] OpenSpec task 3.2 (update `knowledge/devdocs/core_plugin_appsec.md` for client-body-dropped versus unreadable versus unclassified `GetBody`) remains unchecked in the change tasks; expect devdocsimpact before merge if that slice is required for this fork.
