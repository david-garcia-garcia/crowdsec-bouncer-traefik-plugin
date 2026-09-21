# Requirement
IssueKey: 2026-09-17-appsec-query-hardening

## Problem
Five contained defects in `pkg/appsec/query.go` (stale PRs #35 and #43, revalidated on current `master`). When AppSec answers 502/503/504 the response body is not drained, so keep-alive leaks exactly while AppSec is unhealthy. `appsecBodyLimit == 0` is intended as unlimited but forwards a GET with no body. A failed read of the AppSec response bypasses `FailureAction`. Outbound `Content-Length` is copied from the client even when the forwarded body is a different length. HTTP/3 DELETE with `ContentLength < 0` is treated as an unreadable body and dropped or banned.

## Current (code)
- `Query` calls `Do`, then on `err` or `isReverseProxyError` (502/503/504) returns `FailureAction` before `defer drainResponse`. `pkg/appsec/query.go`
- `isReverseProxyError` is 502/503/504. `pkg/appsec/client.go`
- `drainResponse` copies the body to discard and closes it. Keep-alive reuse is tested for 200/403/500 only. `pkg/appsec/query.go` `pkg/appsec/zzz_query_test.go`
- Body copy runs only when `appsecBodyLimit > 0` and `Body != nil`; `0` falls through to GET without a body. `pkg/appsec/query.go`
- ValidateParams allows `AppsecBodyLimit >= 0`; default is 10485760. README does not say zero is unlimited. `pkg/configuration/configuration.go` `README.md`
- `readCappedAppsecBody` error returns `nil, err` (`appsecQuery:readBody`); it does not call `resultForFailureAction`. `pkg/appsec/query.go`
- 500, unreachable, and reverse-proxy statuses do call `resultForFailureAction`. `pkg/appsec/query.go` `pkg/appsec/zzz_failure_action_test.go`
- Client headers are `Add`ed onto the AppSec request after the body is chosen; `Content-Length` is not rebuilt from the bytes sent. `pkg/appsec/query.go`
- `isMethodWithBody` is POST, PUT, PATCH, DELETE. Unreadable HTTP/2–3 body on those methods uses `FailureAction` (ban/captcha drop; passthrough headers-only GET). GET unreadable is not dropped. `pkg/appsec/query.go` `pkg/appsec/zzz_query_test.go`
- Transport is `atomic.Value` (`*transport`); `Query` and the test helper use `currentTransport()` / `transport.Store`. No stored `httpClient` field. `pkg/appsec/client.go` `pkg/appsec/client_http.go` `pkg/appsec/test_client.go`
- `crowdsecAppsecUnreadableBodyBlock` is removed. One `bouncerAppsecFailureAction` covers 500, unreachable, and unreadable body on a method that would have sent a body. `openspec/specs/core_plugin_appsec_failure-action/spec.md`
- Client spec does not define zero body limit or outbound `Content-Length`. `openspec/specs/core_plugin_appsec_client/spec.md`
- Devdoc: 502/503/504 are unreachable; unreadable body uses the same failure action; no zero-limit or DELETE exception. `knowledge/devdocs/core_plugin_appsec.md`

## Desired
- Drain and close the AppSec response before every return that received one (including 502/503/504).
- Treat `appsecBodyLimit == 0` as unlimited: forward the body.
- Route AppSec response-body read failure through `FailureAction` like the other failure classes.
- Rebuild outbound `Content-Length` from the bytes actually sent.
- Remove DELETE from `isMethodWithBody`. POST, PUT, PATCH keep today’s unreadable-body policy.
- Each defect has a test that fails before the fix. Test helper keeps storing into `transport`, not a restored `httpClient` field.
- Update AppSec spec leaves and the AppSec devdoc where they describe unreadable-body methods and a zero body limit.
- PR body cites #35 and #43 as the origin so those PRs can close when this lands.
- No new public config. Do not reintroduce `crowdsecAppsecUnreadableBodyBlock`. Yaegi v0.16: no `atomic.Pointer[T]` as a struct field consumed from another package.

## Affected
- `pkg/appsec/query.go`
- `pkg/appsec/zzz_query_test.go` `pkg/appsec/zzz_failure_action_test.go` `pkg/appsec/test_client.go`
- `openspec/specs/core_plugin_appsec_failure-action/spec.md`
- `openspec/specs/core_plugin_appsec_client/spec.md` (zero body limit / Content-Length if that leaf owns them)
- `knowledge/devdocs/core_plugin_appsec.md`
- README `AppsecBodyLimit` (zero = unlimited) if explore keeps that meaning

## Out of scope
- `pkg/lapi`, `pkg/reclaim`, `pkg/bouncer`, `pkg/captcha`
- Rebase or merge of #35 / #43
- Closing #35 / #43 from this phase (reference only)
- Restoring `httpClient` or a duplicated `appsecKey` on `Client`
- Reintroducing `crowdsecAppsecUnreadableBodyBlock` or any new public knob
- gRPC / streaming body policy (PR #51)
- Changing POST/PUT/PATCH unreadable-body behavior
- Moving `appsecBodyLimit` off the reclaim key
- `atomic.Pointer[T]`

## Unknowns
- How to implement unlimited `0` (skip `LimitReader` vs a max cap) without a new knob.
- Whether read-body failure uses the same error string as unreachable/500 or keeps `appsecQuery:readBody`.
- Whether `Request.ContentLength` must be set in addition to the header.

## Tensions
- Ticket line numbers match current `query.go` on dest `a57c848` (ahead of the ticket’s `340734f`; #64 transport is already there).
- Ticket: `0` means unlimited. README and the client spec do not say that; dest code treats `0` as “do not forward the body”.
- Failure-action spec says unreadable body applies to “a method that would have sent a body”; dest includes DELETE in that set. Ticket removes DELETE only.
- Ticket is independent of #51 (gRPC streams). Do not take that here.
- #35 and #43 conflict on `query.go` / `test_client.go` / AppSec spec and predates #64. Re-implement on current transport; do not restore removed fields.
