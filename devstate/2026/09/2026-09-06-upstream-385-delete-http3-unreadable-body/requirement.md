# Requirement
IssueKey: 2026-09-06-upstream-385-delete-http3-unreadable-body

## Problem
Bodyless `DELETE` requests over HTTP/3 are blocked with 403 by the bouncer before the origin is reached. HTTP/2 for the same request succeeds. No CrowdSec decision or AppSec rule match is logged — the block is from the unreadable-body guard on the AppSec forward path. PR #352 fixed the same false positive for GET/HEAD but left `DELETE` in `isMethodWithBody`.

## Current (code)
- `pkg/appsec/query.go` `isMethodWithBody` returns true for POST, PUT, PATCH, and DELETE (`query.go:81-87`).
- `pkg/appsec/query.go` `isBodyUnreadable` is true when body is non-nil, not `http.NoBody`, `ProtoMajor >= 2`, and `ContentLength < 0` (`query.go:77-78`) — matches quic-go HTTP/3 bodyless requests.
- `pkg/appsec/query.go` `newAppsecBodyRequest` drops unreadable bodies for methods in `isMethodWithBody` when failure action is not passthrough, returning `appsecQuery:unreadableBody dropped` (`query.go:146-148`).
- `pkg/bouncer/bouncer.go` `applyAppsecServeHTTP` treats that error as AppSec failure and calls `handleBanServeHTTP` (403) before origin (`bouncer.go:306-314`).
- `pkg/appsec/query_test.go` `Test_appsecQuery_unreadableBodyGetNotDropped` covers GET only; no DELETE regression test (`query_test.go:124-145`).
- Default operator config uses ban failure action via `configuration.EffectiveFailureAction` when unset (`pkg/configuration/configuration.go` — not re-verified line-by-line here).

## Desired
- Remove `DELETE` from `isMethodWithBody` so bodyless HTTP/3 DELETE requests are forwarded to AppSec as GET (no body), matching GET/HEAD behavior after #351.
- Add a test mirroring `Test_appsecQuery_unreadableBodyGetNotDropped` for DELETE.
- Do not change operator config keys or defaults.

## Affected
- `pkg/appsec/query.go` (`isMethodWithBody`, `newAppsecBodyRequest` branch)
- `pkg/appsec/query_test.go` (new DELETE unreadable-body test)
- Indirect: `pkg/bouncer/bouncer.go` (403 ban path no longer hit for this case)

## Out of scope
- Changing `crowdsecAppsecFailureAction` default or adding a per-method unreadable-body toggle.
- Altering POST/PUT/PATCH gRPC/stream protection (#323/#332).
- Upstream lua-cs-bouncer parity.
- Broader AppSec query hardening beyond this DELETE gate.

## Unknowns
- Whether a DELETE that intentionally carries a body over HTTP/3 should still be dropped when unreadable (ticket assumes bodyless DELETE is the norm; no DELETE-with-body test requested).

## Tensions
- Ticket workaround names `crowdsecAppsecUnreadableBodyBlock: false`; assessment names `crowdsecAppsecFailureAction: passthrough` — both disable the drop globally, not DELETE-only.
- Upstream issue cites upstream config key `crowdsecAppsecUnreadableBodyBlock`; this fork maps the behavior to `crowdsecAppsecFailureAction` passthrough vs ban.
