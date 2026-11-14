# Delivery

## Motivation
Upstream issue: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/405

With AppSec enabled, the plugin copies the client body of POST, PUT, PATCH and DELETE requests to AppSec before the request reaches the service. It sorted an HTTP/2 or HTTP/3 body with no `Content-Length` header into a separate "unreadable" class without ever trying to read it. `Content-Length` is optional in HTTP/2 and HTTP/3, so this class depended only on a header the client controls.

The visible failure is the one in #405. `restic init` against `rest-server` sends `POST <repo>/?create=true` over HTTP/2 with an empty body and no `Content-Length`. With the default `bouncerAppsecFailureAction: ban`, the plugin dropped every POST, PUT and PATCH in this class with a 403 and never asked AppSec. The drop was logged at Debug only, so the operator saw a silent 403 for a request whose body was empty and cost nothing to read.

The same class opened inspection gaps:

- With `passthrough`, an "unreadable" POST, PUT or PATCH went to AppSec headers-only, and the body reached the service uninspected. Any client could get that bypass by leaving out `Content-Length`. The fallback suggested on #405 (`crowdsecAppsecUnreadableBodyBlock: false`) is this same bypass.
- An HTTP/2 or HTTP/3 DELETE without `Content-Length` went to AppSec headers-only even with `ban`, while a DELETE with the header had its body inspected. A test locked this behaviour in. This is inferred from the code and that test; it was not reproduced end to end.
- `bouncerAppsecFailureAction` covered both "AppSec failed" (unreachable, 500) and "the client sent no length". An operator could not let restic through without also failing open whenever AppSec is down.

If left alone, restic and similar HTTP/2 clients keep getting unexplained 403s. The only way out for operators also lets any client skip body inspection by dropping one optional header.

Priority: P2 — real operator and end-user pain (restic blocked with a silent 403), with a workaround whose blast radius is limited to deployments that opt into `passthrough`

## Implementation
Bodies of unknown length now go through the same read path as every other body. The "unreadable" class and its separate POST/PUT/PATCH drop set are gone. `isMethodWithForwardableBody` (POST, PUT, PATCH, DELETE) is the only method gate, whatever the HTTP version or `Content-Length`. The read is always capped with `io.LimitReader` at `appsecBodyLimit`. `configuration.EffectiveAppsecBodyLimit` maps a value `<= 0` to 10485760 in both `appsec.Prepare` and `appsec.New`, so the reclaim identity also sees the capped value. There is no longer an unlimited mode.

A body with `ContentLength < 0` (HTTP/1.1 chunked, HTTP/2 or HTTP/3 without the header) is read under a total deadline set by the new key `appsecBodyReadTimeoutSeconds` (default 30, values below 1 rejected). The key is stored on the AppSec `Client` and added to its reclaim identity. A `time.AfterFunc` timer is armed before the capped read. When it fires, it calls `SetReadDeadline(time.Now())` on an `http.ResponseController` that the bouncer builds from its `rw` and passes in through a new third argument of `Client.Query`. If the controller is nil or returns an error, the timer closes the request body instead. After the read, `!timer.Stop()` is the only test for "the deadline fired". It runs before the client-disconnect check, so a cut read cannot be taken for a disconnect, and a read that finished in a race with the timer still counts as a timeout. The fired case returns the new sentinel `appsec.ErrBodyReadTimeout` and logs a WARN, debounced to 5 s, that names `bypassAppsec`. Bodies with a declared `Content-Length` keep their current behaviour and get no plugin deadline. The code uses no goroutine, `select` or atomic type, to stay within Yaegi v0.16.1 limits.

`applyAppsecServeHTTP` checks for `ErrBodyReadTimeout` before any failure-action outcome and serves it as a ban: reason `ReasonAPPSEC`, remediation header `ban:appsec-body-timeout`, usage-metrics origin `plugin:appsec_body_timeout`, and a warning when it supersedes a captcha. `bouncerAppsecFailureAction` now covers only AppSec failures.

Known limitation: on Traefik v3.7.11 the controller does not reach the HTTP/1.1 connection, so a stalled chunked read there is not cut at the deadline. The request is still blocked, but only when the client ends or abandons its body, or when Traefik's `readTimeout` expires. HTTP/2 is cut at the deadline. HTTP/3 was not measured. This is recorded in the deviations and in `knowledge/debt/2026-11-14-appsec-body-timeout-http1-cut-behind-traefik.md`.

Tests:

- Unit tests cover the read path, the deadline and the `<= 0` limit, plus a Yaegi run of the deadline path.
- A bouncer test covers the ban.
- The mock e2e runs a real Traefik binary. It now expects 200 for clean HTTP/2 bodies without `Content-Length`, and 403 from the AppSec verdict for bad HTTP/2 POST, HTTP/2 DELETE and HTTP/1.1 chunked bodies.
- On a `passthrough` route with a 2 s timeout, the e2e checks that a late HTTP/1.1 body gets 403 with `ban:appsec-body-timeout`, and that an HTTP/2 stream gets 403 within 3 s according to the access log.

## What this changes
**Operators.** A new key `appsecBodyReadTimeoutSeconds` (default `30`, minimum `1`) blocks any body without `Content-Length` that does not arrive in time, whatever `bouncerAppsecFailureAction` says (watch the `ban:appsec-body-timeout` header, the `plugin:appsec_body_timeout` metrics origin and the WARN log line); routes with streaming request bodies, such as gRPC client or bidirectional streams, Connect streaming and long uploads, now need a `bouncerActionRules` `bypassAppsec` rule; `appsecBodyLimit: 0` now caps at 10 MiB instead of sending the whole body, and negative values are accepted and treated the same way instead of failing validation.

**Admin users.** None.

**Developers.** `appsec.Client.Query` takes a third `*http.ResponseController` argument (nil is allowed), and the new exported names are `appsec.ErrBodyReadTimeout` (which callers must check before applying the failure action), `configuration.EffectiveAppsecBodyLimit`, `DefaultAppsecBodyLimit`, `DefaultAppsecBodyReadTimeoutSeconds`, `Config.AppsecBodyReadTimeoutSeconds` and `lapi.OriginPluginAppsecBodyTimeout`.

**End users.** HTTP/2 and HTTP/3 clients that send a body without `Content-Length` (for example `restic init`) no longer get an automatic 403: AppSec inspects the body and decides, while request bodies that keep streaming past the timeout are blocked unless the route is excluded.
