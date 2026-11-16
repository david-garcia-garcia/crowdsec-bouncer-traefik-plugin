# WAF-leg shared request rules

## Language

**WAF leg**:
A leg that copies the inbound request to an inspecting backend: AppSec (CrowdSec AppSec listener) or ModSec (CRS sidecar).
_Avoid_: putting LAPI or captcha under this name

**Unreadable body**:
A body on HTTP/2 or later with unknown length (`wafhop.IsBodyUnreadable`): gRPC and other streams. No WAF leg reads it.
_Avoid_: a private `isBodyUnreadable` in a leg package

## Overview

`pkg/wafhop` is the one place for the request-side business the WAF legs share. Settings stay per leg: AppSec passes `appsecBodyLimit` with `TruncateAtLimit`, ModSec passes `modsecBodyLimit` with `RejectOverLimit`, and each leg applies its own failure action (`bouncerAppsecFailureAction`, `bouncerModsecFailureAction`). Spec: `core_plugin_wafhop_shared-request`.

## How to use

- Check `wafhop.HasBody` and `wafhop.IsBodyUnreadable` before reading. On an unreadable body with `wafhop.IsMethodWithBody`, apply the leg's own failure action unless it is `passthrough`; otherwise inspect headers only. Both legs follow this one rule.
- Buffer with `wafhop.ReadBody(req, limit, mode)`. It restores `req.Body` for `next`. Do not wrap `req.Body` yourself, and do not add a buffer pool: a whole body buffered by AppSec is reused by ModSec with no second copy.
- Return `wafhop.ErrClientDisconnected` / `wafhop.ErrClientBodyRead` unwritten to the bouncer. `handleClientDisconnectedServeHTTP` and `handleClientBodyReadServeHTTP` (`pkg/bouncer/bouncer_serve_waf.go`) answer them for every leg. `wafhop.ErrBodyTooLarge` (`modsecurity.ErrBodyTooLarge`) also comes back unwritten; `serveModSec` answers 413.
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
- `ReadBody` reads `limit + 1` bytes to tell "exactly at the limit" from "over it". Do not pass 0 into `io.LimitReader` (`N <= 0` is immediate EOF); `ReadBody` treats 0 as no cap.
- A reused body still goes through this leg's limit: AppSec may buffer 10 MiB whole and ModSec must still answer 413 over 8 MiB.
- There is no method list for bodies. ModSec forwards any readable body to the sidecar and CRS decides (rules 920170/920171 block a body on GET/HEAD). Do not add a deny-verbs check to a leg or to this package.
