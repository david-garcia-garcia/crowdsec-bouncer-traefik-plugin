# Explore
IssueKey: 2026-09-17-appsec-query-hardening

## Concepts

Five defects share `pkg/appsec/query.go` on the AppSec forward round-trip. Transport is already `atomic.Value` + `currentTransport()` (#64). No active OpenSpec change. Sister PRs #35 (drain, limit `0`, read-error FA, Content-Length) and #43 (DELETE out of `isMethodWithBody`) are stale against this dest; re-implement, do not rebase.

```
Do(req)
  ├─ err (res typically nil) ──► FailureAction  [no body]
  ├─ 502/503/504 ──► FailureAction  [body exists; dest skips drain]
  ├─ 500 ──► FailureAction + drain
  ├─ readCappedAppsecBody err ──► raw error  [bypasses FA]
  └─ interpret JSON
```

`isMethodWithBody` is only the unreadable-body drop gate (POST/PUT/PATCH/DELETE). Readable-body copy is `appsecBodyLimit > 0 && Body != nil` and does not consult that set. CrowdSec protocol: GET unless the original has a body, then POST (`ext_crowdsec_appsec_protocol`). Client IP is already chosen before Query (`pkg/ip.GetRemoteIP` → `clientRequest.remoteIP`).

Consumed: `core_plugin_appsec` (enough to call Query; desired contract is missing there — implement updates the packet). Research written this phase: `std_go_io_limit-reader`, `std_go_net-http_keep-alive-drain`, `std_go_net-http_request-content-length`. Not process-lifetime work; did not propose `sync.Once` or package globals.

## Decisions

- Drain every non-nil `Do` response before any return, including 502/503/504. Transport errors have no body. Keep #64 `currentTransport()`; do not restore `httpClient` / `appsecKey` fields.
- `crowdsecAppsecBodyLimit == 0` is unlimited: skip `LimitReader` (`N <= 0` is immediate EOF — `std_go_io_limit-reader`); `io.ReadAll` the body; restore it for origin. Default 10 MiB when omitted. No new knob. No invented max cap. README documents `0` = unlimited.
- `readCappedAppsecBody` **io** errors go through `resultForFailureAction` with `err.Error()` (keep `appsecQuery:readBody`). Log `appsecQuery:failure` like 500. Oversized-body cap stays as today (200 allow / non-200 error, not FA).
- After the forwarded bytes exist, omit client `Content-Length` and `Transfer-Encoding` from the copy; set `Request.ContentLength` and the header from those bytes. Go 1.25.6 Transport already writes the field and suppresses those header names (`std_go_net-http_request-content-length`); rebuild is the durable contract. Do not add a general hop-by-hop filter.
- Remove DELETE only from `isMethodWithBody`. Do not gate the readable-body copy on that set (would change readable DELETE/GET forward). Independent of #51.
- Tests that fail before the fix; helper stores into `transport`, not a restored `httpClient` field. Yaegi: keep `atomic.Value`, no `atomic.Pointer[T]`.
- Specs later: fold `core_plugin_appsec_client` (drain, zero limit, Content-Length) and `core_plugin_appsec_failure-action` (read errors; unreadable methods POST/PUT/PATCH). Cite #35 and #43 on the PR body.

**Measured:** `go test ./pkg/appsec/ -count=1` passed (0.943s). Defects untested, so green. Drain: `Query` returns on 502/503/504 before `defer drainResponse` (`query.go`). Keep-alive reuse covers 200/403/500 only. Limit `0` falls through to GET. Read error returns `nil, err`. Headers `Add` after body choose. DELETE is in `isMethodWithBody`. GET unreadable is not dropped (existing test).

## Open questions

- Q: How to implement unlimited `crowdsecAppsecBodyLimit` `0` without a new knob?
  Decision: resolved — skip `io.LimitReader`; `io.ReadAll` the client body when `appsecBodyLimit == 0`; restore the body for origin. Do not pass `0` into `LimitReader`. Do not invent a max cap.
  By: explore

- Q: Does a response-body read failure keep `appsecQuery:readBody` or reuse the unreachable/500 string?
  Decision: resolved — keep `appsecQuery:readBody` via `resultForFailureAction(pol.FailureAction, err.Error())`; log `appsecQuery:failure` like 500. Do not collapse to `appsecQuery:unreachable`.
  By: explore

- Q: Must `Request.ContentLength` be set in addition to the `Content-Length` header?
  Decision: resolved — set both from the bytes actually forwarded (`NewRequest` on `*bytes.Buffer` already sets the field; overwrite the header after the client copy). Omit client `Content-Length` and `Transfer-Encoding` from `Add`.
  By: explore

- Q: Who already owns the client address Query puts on `X-Crowdsec-Appsec-Ip`?
  Decision: resolved — `pkg/ip.GetRemoteIP` owns it; `pkg/bouncer` passes `clientRequest.remoteIP` into `Query`. Reuse that `ip` argument. Do not reconstruct from `RemoteAddr` or Host.
  By: explore

- Q: Should the header copy also strip hop-by-hop names (Connection, Upgrade, …) like PR #35?
  Decision: assumed — no. This ticket asks to rebuild `Content-Length`. Skip only body-size headers (`Content-Length`, `Transfer-Encoding`). Do not add a hop-by-hop filter.
  By: explore

- Q: Do oversized AppSec response bodies (`responseBodyTooLarge`) go through FailureAction?
  Decision: assumed — no. Only `io.ReadAll` errors on the AppSec body. Oversized 200 allow and oversized non-200 error stay as dest today.
  By: explore

- Q: Should readable-body forward be gated on `isMethodWithBody` (PR #35 `readForwardBody`)?
  Decision: assumed — no. Only delete DELETE from the unreadable-body set. Keep today’s `Body != nil` copy for any method when a body is readable (including limit `0`).
  By: explore

- Q: Any new public knob (including restoring `crowdsecAppsecUnreadableBodyBlock`)?
  Decision: assumed — none. `0` already means unlimited on the existing key. Do not reintroduce the removed bool.
  By: explore

- Q: Does this run take gRPC / streaming body policy (PR #51)?
  Decision: assumed — no. Out of scope. A DELETE must not be dropped for a body it never sends, regardless of #51.
  By: explore
