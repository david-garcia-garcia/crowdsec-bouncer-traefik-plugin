## Why

Five contained defects in `pkg/appsec/query.go` leak keep-alive while AppSec is unhealthy, drop a body the operator marked unlimited, skip `FailureAction` on a failed AppSec body read, send a stale `Content-Length`, and treat HTTP/3 DELETE as an unreadable-body drop. Sister PRs #35 and #43 are stale against current `master` (`atomic.Value` transport from #64); re-implement, do not rebase.

## What Changes

- Drain and close every non-nil AppSec `Do` response before return, including HTTP 502/503/504. Transport errors have no body.
- Treat `crowdsecAppsecBodyLimit == 0` as unlimited: skip `io.LimitReader`, `io.ReadAll` the client body, restore it for origin. Default 10 MiB when omitted. README documents `0` = unlimited.
- Route AppSec response-body **io** errors through `resultForFailureAction` with `err.Error()` (keep `appsecQuery:readBody`). Log `appsecQuery:failure` like 500. Oversized-body cap stays as today (200 allow / non-200 error, not FA).
- After the forwarded bytes exist, omit client `Content-Length` and `Transfer-Encoding` from the header copy; set `Request.ContentLength` and the header from those bytes.
- Remove DELETE only from `isMethodWithBody`. POST, PUT, PATCH keep today’s unreadable-body policy. Do not gate the readable-body copy on that set.
- **Amendment, folded from #35 (owner closed #35 as superseded):** strip hop-by-hop headers (`Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`) before forwarding; gate the readable-body copy on a new `isMethodWithForwardableBody` (POST, PUT, PATCH, DELETE) so a GET carrying a body is no longer forwarded as a POST. `isMethodWithBody` and the unreadable-body drop policy are untouched; `crowdsecAppsecUnreadableBodyBlock` is still out of scope (#51).
- Each defect has a test that fails before the fix. Test helper keeps storing into `transport`, not a restored `httpClient` field.
- No new public config. Do not reintroduce `crowdsecAppsecUnreadableBodyBlock`. Yaegi v0.16: no `atomic.Pointer[T]` as a struct field consumed from another package.
- PR body cites #35 and #43 as the origin.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_appsec_client`: drain every non-nil AppSec response (including 502/503/504); body limit `0` is unlimited; rebuild outbound `Content-Length` from the bytes sent (POST branch only); strip hop-by-hop headers on the forward path; copy a readable body only on POST, PUT, PATCH, DELETE.
- `core_plugin_appsec_failure-action`: AppSec response-body io errors use `FailureAction`; unreadable-body methods are POST, PUT, PATCH (DELETE removed).

## Impact

- `pkg/appsec/query.go`, `pkg/appsec/zzz_query_test.go`, `pkg/appsec/zzz_failure_action_test.go`, `pkg/appsec/test_client.go` (helper stays `transport.Store`).
- `openspec/specs/core_plugin_appsec_client`, `openspec/specs/core_plugin_appsec_failure-action`.
- README `CrowdsecAppsecBodyLimit` (`0` = unlimited; only POST/PUT/PATCH/DELETE bodies are forwarded).
- Usage `knowledge/devdocs/core_plugin_appsec.md` after apply (implement / devdocsimpact).
- Do not edit `pkg/lapi`, `pkg/reclaim`, `pkg/bouncer`, `pkg/captcha`. Do not restore `httpClient` / `appsecKey`. Do not take gRPC / streaming (#51).
