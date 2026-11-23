# WAF-leg shared request rules

## Language

**WAF leg**:
A leg that copies the inbound request to an inspecting backend: AppSec (CrowdSec AppSec listener) or ModSec (CRS sidecar).
_Avoid_: putting LAPI or captcha under this name

**Body read deadline**:
The total time one WAF leg waits to receive a body of unknown length (`ContentLength < 0`: HTTP/1.1 chunked, HTTP/2 or HTTP/3 without the header) up to its body limit: `appsecBodyReadTimeoutSeconds` or `modsecBodyReadTimeoutSeconds`, default 30. Counted from the start of that leg's read, not an idle timeout. Expiry is `wafhop.ErrBodyReadTimeout`. Not a WAF failure and not the failure action.
_Avoid_: unreadable body, streaming drop, idle timeout, a per-leg private timer

## Overview

`pkg/wafhop` is the one place for the request-side business the WAF legs share. Settings stay per leg: AppSec passes `appsecBodyLimit` with `TruncateAtLimit` and `appsecBodyReadTimeoutSeconds`, ModSec passes `modsecBodyLimit` with `RejectOverLimit` and `modsecBodyReadTimeoutSeconds`, and each leg applies its own failure action (`bouncerAppsecFailureAction`, `bouncerModsecFailureAction`) to WAF failures only. Spec: `core_plugin_wafhop_shared-request`.

## How to use

- Check `wafhop.HasBody`, then read. There is no length or HTTP-version check: a body without `Content-Length` is read and inspected like one with it, on every method the leg forwards. A body never selects the failure action.
- Buffer with `wafhop.ReadBody(req, limit, mode, ctrl, timeout)`. `limit` is the leg's effective limit and must be at least 1 (no uncapped mode). `ctrl` is `http.NewResponseController(rw)`, built by the bouncer (the only owner of `rw`) and passed through `Query` / `Inspect`; tests pass `nil`. `timeout` is the leg's body read deadline. It restores `req.Body` for `next`. Do not wrap `req.Body` yourself, and do not add a buffer pool: a whole body buffered by AppSec is reused by ModSec with no second copy and no timer.
- Return `wafhop.ErrBodyReadTimeout` / `wafhop.ErrClientDisconnected` / `wafhop.ErrClientBodyRead` unwritten to the bouncer, before admission (no gate ticket, no Record). `handleBodyReadTimeoutServeHTTP` (400, `error:body-read-timeout`, debounced WARN per leg naming its timeout key and bypass action), `handleClientDisconnectedServeHTTP`, and `handleClientBodyReadServeHTTP` (`pkg/bouncer/bouncer_serve_waf.go`) answer them for every leg, whatever the failure action. `wafhop.ErrBodyTooLarge` (`modsecurity.ErrBodyTooLarge`) also comes back unwritten; `serveModSec` answers 413.
- Around the WAF call, classify a cancel with `wafhop.IsInboundCanceled`, not `IsClientGone`: the WAF client's `Client.Timeout` is `context.DeadlineExceeded` and is a WAF failure.
- Build the WAF copy with `wafhop.CopyEndToEndHeaders(dst, req.Header, "Content-Length")`. Use `wafhop.IsHopByHopHeader` when relaying WAF headers to the client.
- Record gate outcomes with `admission.Gate.Record`, which logs a failed Report.

## Key files

- `pkg/wafhop/body.go`
- `pkg/wafhop/header.go`
- `pkg/appsec/query.go` (`newAppsecBodyRequest`)
- `pkg/modsecurity/inspect.go` (`Inspect`)
- `pkg/bouncer/bouncer_serve_waf.go`

## Gotchas

- Do not strip names the client lists in `Connection`, and do not turn the hop-by-hop list into a pattern (`Proxy-*`): both let a client hide a header from the WAF.
- `ReadBody` reads `limit + 1` bytes to tell "exactly at the limit" from "over it". A non-positive `limit` is a caller bug: resolve the leg default first (`configuration.EffectiveAppsecBodyLimit`; ModSec validates `>= 1`). Do not pass 0 into `io.LimitReader` (`N <= 0` is immediate EOF).
- Classify the deadline before the disconnect: on HTTP/1.1 `SetReadDeadline` also cancels the request context, which `IsClientGone` would read as a client that left. `bufferBody` reports `timedOut` from `!timer.Stop()` and `ReadBody` checks it first.
- The deadline only cuts. The timer callback (`cutBodyRead`) sets the connection read deadline to now, or closes the body when `ctrl` is nil or `SetReadDeadline` fails (that cuts HTTP/2 only). The success path never touches the read deadline, so Traefik's `readTimeout` still bounds the rest of an oversize body. A body with a declared `Content-Length` starts no timer.
- Keep `ctrl` the concrete `*http.ResponseController`. Under Yaegi an interface holding it panics in the `time.AfterFunc` callback (`pkg/wafhop/zzz_yaegi_body_read_deadline_test.go`). No `select` and no goroutine of our own on this path.
- A reused body still goes through this leg's limit: AppSec may buffer 10 MiB whole and ModSec must still answer 413 over 8 MiB.
- There is no method list for bodies. ModSec forwards any readable body to the sidecar and CRS decides (rules 920170/920171 block a body on GET/HEAD). Do not add a deny-verbs check to a leg or to this package.
