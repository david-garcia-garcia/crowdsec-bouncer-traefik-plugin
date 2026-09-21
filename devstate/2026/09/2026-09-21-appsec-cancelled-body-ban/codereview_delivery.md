# Delivery

## Motivation

With AppSec enabled, the bouncer buffers readable POST, PUT, PATCH, and DELETE bodies before calling the AppSec listener. That path matches normal forwardable requests: known or positive `Content-Length`, body not classified as unreadable under HTTP/2 or HTTP/3 streaming rules.

If the client stops sending the body mid-copy (HTTP/2 stream cancel, request context canceled, truncated body versus `Content-Length`), `io.ReadAll` on the tee/limit reader fails. Previously the plugin treated that as an AppSec query failure and answered HTTP 403 with `ReasonAPPSEC`, even though AppSec never received the request. Operators who set `crowdsecAppsecFailureAction: passthrough` still hit that ban path.

Upstream report: [maxlerebourg/crowdsec-bouncer-traefik-plugin#395](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/395).

Leaving it in place produces false AppSec bans on benign client disconnects, undermines the unified failure-action knob for a common edge case, and can block or confuse end users who already abandoned the request.

Priority: P2 — real operator and end-user pain on client disconnect, with `FailureAction` intended as the control but ineffective on this path today.

## Implementation

After `io.ReadAll` fails while buffering a forwardable body, read errors classified as client-gone (`context.Canceled`, `context.DeadlineExceeded`, `io.ErrUnexpectedEOF` via `errors.Is`) become `ErrClientDisconnected`. `Query` returns that sentinel without calling AppSec and without `crowdsecAppsecFailureAction`. The bouncer logs TRACE (`client disconnected while buffering AppSec body`), sets `remediationHeadersCustomName` to `error:client-disconnected` when that header is configured, does not `WriteHeader`, does not increment LAPI dropped metrics, and does not call origin. Unclassified read faults keep `appsecQuery:GetBody` wrapping so they still follow today’s ban wiring in `applyAppsecServeHTTP`. Regression coverage lives in `pkg/appsec/zzz_query_test.go` and `pkg/bouncer/zzz_bouncer_test.go` (cites #395).

## What this changes
**Operators.** A client that disconnects mid-body is no longer logged as a CrowdSec 403/AppSec ban. If `remediationHeadersCustomName` is set, Traefik access logs can record `error:client-disconnected` (include that header in Traefik access-log fields). Plugin log is TRACE only.
**Admin users.** None.
**Developers.** `Query` returns `ErrClientDisconnected` for classified client-gone body reads; unclassified body read errors remain `appsecQuery:GetBody`.
**End users.** Mid-upload disconnect is not answered with a false AppSec 403.

## Stored data model
None.

## Findings
None.
