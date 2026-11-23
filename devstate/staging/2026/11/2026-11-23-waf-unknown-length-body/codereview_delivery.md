# Delivery

## Motivation

Reported upstream as [maxlerebourg/crowdsec-bouncer-traefik-plugin#405](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/405): "Silent 403 on HTTP/2 requests with an empty body (restic repo creation)". This PR supersedes [#204](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/204). #204 fixed the AppSec side only. It was built on a base older than the per-leg split (#219, #221), the shared `pkg/wafhop` package and the ModSec leg (#190), and it now conflicts with `master`.

Both WAF legs read the client body before they judge a request. `wafhop.IsBodyUnreadable` puts any HTTP/2 or HTTP/3 request that has a body but no `Content-Length` (`ContentLength < 0`) into an "unreadable" class, and nothing in that class is ever read. For POST, PUT and PATCH, each leg then hands the request to its failure action, which is meant for "the WAF gave no answer":

- **AppSec** (`bouncerAppsecFailureAction`, default `ban`): the request gets a 403 and AppSec is never queried. `restic init` against `rest-server` sends `POST <repo>/?create=true` over HTTP/2 with an empty body and no `Content-Length`, so it is silently banned. With `passthrough`, AppSec gets the headers only and the body reaches origin uninspected.
- **ModSec** (`bouncerModsecFailureAction`, default `passthrough`): the sidecar gets the headers only. With default settings, any client that leaves out `Content-Length` on HTTP/2 or HTTP/3 gets its body past CRS uninspected.
- **DELETE**, and any other method outside POST/PUT/PATCH, without `Content-Length` goes headers-only on both legs whatever the failure action. The same DELETE with the header has its body inspected.

`Content-Length` is optional in HTTP/2 and HTTP/3, so the client decides whether its body gets inspected. Because one failure action covers both "the WAF failed" and "the client sent no length", an operator cannot let restic through without also failing open when the WAF is down. HTTP/1.1 chunked bodies, which also have no length, are read today with no plugin deadline at all.

If nothing changes, ModSec's default setup has a body-inspection bypass that any client can trigger, AppSec's default setup blocks legitimate HTTP/2 clients that send no length, and the only workaround for one of these problems opens the other.

Priority: P1 — production is unsafe today: with ModSec's default failure action, any HTTP/2 or HTTP/3 client can skip body inspection by leaving out `Content-Length`.

## Implementation

Bodies of unknown length are no longer a separate class. `IsBodyUnreadable`, `IsMethodWithBody`, AppSec's `errUnreadableBody` and both drop branches are gone. Each leg reads every body it forwards through the one shared `wafhop.ReadBody` (AppSec: POST, PUT, PATCH, DELETE, truncated at `appsecBodyLimit`; ModSec: any method, 413 over `modsecBodyLimit`). A body that AppSec already read in full is reused by ModSec, with no second read and no second timer.

When `ContentLength < 0`, on any protocol (HTTP/1.1 chunked, HTTP/2, h2c, HTTP/3), `ReadBody` reads under a total deadline set per leg: `appsecBodyReadTimeoutSeconds` / `modsecBodyReadTimeoutSeconds`, default 30, minimum 1. Each key lives on its leg's Client and in that leg's reclaim identity, because leg instances are shared by owner. The deadline works like this:

- A `time.AfterFunc` timer is armed only while this call actually reads from the client.
- When the timer fires, it calls `SetReadDeadline(time.Now())` on a per-request `*http.ResponseController` that the bouncer builds from `rw`. If there is no controller, or the call fails, it closes the body instead.
- After the read, `fired := !timer.Stop()` is checked before `IsClientGone`. On HTTP/1.1 the cut also cancels the request context, so checking for a disconnect first would wrongly treat the timeout as a client that left.
- The success path never sets a deadline, so Traefik's own `readTimeout` still bounds the rest of an oversize body.
- There is no goroutine, `select` or atomic type of the plugin's own, so the code runs under Yaegi.
- The parameter is the concrete controller, not an interface: under Yaegi v0.16.1, a nil check on an interpreted interface that holds the controller panics inside the timer goroutine (measured).

When the deadline fires, both legs return a new `wafhop.ErrBodyReadTimeout`. The bouncer answers it in one shared handler: HTTP 400, header `error:body-read-timeout`, no ban, no dropped metrics, no failure action, no gate record, and `next` is not called. It also writes a debounced (5 s) WARN per leg with `ip`, `method`, `host`, `path` (no query string) and `timeoutSeconds`, naming the leg's timeout key and its `bypassAppsec` / `bypassModsec` (or `bypass`) action. The answer is 400 rather than a ban because `master` already answers every "client body did not arrive whole" case (Traefik's `readTimeout` included) as 400 with no ban. The plugin's deadline is the same symptom on a shorter clock, and a ban would count a slow client as a WAF drop. 408 was rejected because clients retry it automatically. Each failure action now covers only a WAF that gave no verdict. `appsecBodyLimit <= 0` maps to 10 MiB through `configuration.EffectiveAppsecBodyLimit` (in `Prepare`, so the reclaim identity hashes 0, negative values and 10485760 the same, and in `New`). As a result, `ReadBody` no longer has a "no cap" mode.

Why not the alternatives (upstream PRs re-read on their current heads; both still open):

- **Upstream [#407](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/407):**
  - The wait is hardcoded (`time.Second`).
  - `appsecBodyLimit <= 0` still drops without reading.
  - `crowdsecAppsecUnreadableBodyBlock: false` and DELETE without `Content-Length` stay headers-only, so the client's signal still reduces inspection.
  - A read that times out runs in its own goroutine that nothing cancels. On Go's HTTP/2 server it ends when the stream closes; on an HTTP/1.1-shaped path it would hold the response. This plugin also avoids starting goroutines on the request path under Yaegi.
- **Upstream [#434](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/434):**
  - The client-controlled `Content-Type` picks the path (`application/grpc`, `application/grpc+*`, `application/connect+*`; a duplicated `Content-Type` counts as readable). With the flag set to `false`, a request that claims gRPC skips body inspection.
  - There is no plugin deadline: a stalled body fails only at Traefik's `readTimeout` (60 s by default).
  - gRPC unary calls are blocked by default.
  - HTTP/2/3 GET and DELETE without `Content-Length` stay headers-only.
- **Setting `crowdsecAppsecUnreadableBodyBlock: false`** (the workaround the #405 author verified): any client that leaves out `Content-Length` skips body inspection. That is the bypass this change removes.

Proof:

- Unit tests in `wafhop`, `appsec`, `modsecurity`, `configuration` and `bouncer` cover the restic shape reaching origin on both legs, a 400 under every failure action, and the WARN debounce.
- A Yaegi v0.16.1 test runs the deadline path.
- The mock AppSec e2e, on Traefik v3.7.19, measured a 400 at 2.0 s for stalled HTTP/1.1 chunked and HTTP/2 bodies with a 2 s timeout. #204 had recorded that an HTTP/1.1 read could not be cut on v3.7.11; that limitation does not reproduce here.
- The real ModSec e2e over h2c lets the restic shape through, blocks an XSS body sent without a length, and answers a stalled body with 400 `error:body-read-timeout`.
- HTTP/3 was not measured; the docs say "expected".

## What this changes
**Operators.** Breaking: `appsecBodyLimit` 0 or negative now means 10 MiB (0 used to mean no cap, negative was a validation error); bodies without `Content-Length` (HTTP/1.1 chunked, HTTP/2, HTTP/3) are now read, capped and inspected on both legs, so ModSec inspects bodies it used to pass headers-only; each leg's new `appsecBodyReadTimeoutSeconds` / `modsecBodyReadTimeoutSeconds` (default 30, minimum 1) answers a body that does not arrive in time with HTTP 400 `error:body-read-timeout` and a WARN, whatever the failure action says, so routes that stream request bodies (gRPC client/bidi, Connect streaming, slow uploads) need a `bouncerActionRules` `bypassAppsec` / `bypassModsec` (or `bypass`) rule or a higher timeout; and the failure actions no longer cover the client's body.
**Admin users.** None.
**Developers.** `appsec.Client.Query` gains a `*http.ResponseController` parameter, `modsecurity.Client.Inspect` takes one instead of `failureAction`, `wafhop.ReadBody` takes the controller and a timeout and requires `limit >= 1`, `wafhop.IsBodyUnreadable` / `IsMethodWithBody` are removed, and the new `ErrBodyReadTimeout` (in `wafhop`, aliased in `appsec`) must be handled apart from `ErrClientBodyRead`.
**End users.** A client that sends a body without `Content-Length`, such as `restic init` over HTTP/2, now reaches the application after inspection instead of getting a silent 403, and a request body that never ends within the timeout gets HTTP 400.
