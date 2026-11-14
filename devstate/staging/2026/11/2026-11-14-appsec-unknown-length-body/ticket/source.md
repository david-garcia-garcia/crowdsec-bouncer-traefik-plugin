# AppSec: inspect request bodies of unknown length instead of dropping them

Upstream issue: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/405
("Silent 403 on HTTP/2 requests with an empty body (restic repo creation) — crowdsecAppsecUnreadableBodyBlock defaults to true").
Upstream candidate fixes, both OPEN and not merged:
- https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/407 ("inspect an unreadable body that ends in time instead of dropping it")
- https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/434 ("buffer non-streaming HTTP/2+ request bodies without Content-Length")

The delivery card and the PR MUST reference upstream issue #405 by URL.

## Problem (verified in this fork on master)

1. `pkg/appsec/query.go` `isBodyUnreadable` classifies any HTTP/2 or HTTP/3 request with a body and `ContentLength < 0` (no `Content-Length` header) as "unreadable" without trying to read it. `newAppsecBodyRequest` then returns `appsecQuery:unreadableBody dropped` for POST, PUT and PATCH unless `bouncerAppsecFailureAction` is `passthrough`. With the default `ban` the client gets a 403 and AppSec is never queried. `pkg/bouncer/bouncer.go` `applyAppsecServeHTTP` logs it at Debug only. Real-world victim: `restic init` against `rest-server` sends `POST <repo>/?create=true` over HTTP/2 with an empty body and no `Content-Length`.
2. The classification depends only on a client-controlled signal (a missing header; `Content-Length` is optional in HTTP/2/3). With `passthrough`, any client can strip `Content-Length` and the body reaches the backend without inspection: a WAF bypass. Upstream's suggested workaround (`crowdsecAppsecUnreadableBodyBlock: false`) is exactly that bypass.
3. DELETE: `isMethodWithForwardableBody` inspects a DELETE body when `Content-Length` is present, but an HTTP/2/3 DELETE without `Content-Length` is classified unreadable, is not a drop candidate (`isMethodWithBody` excludes DELETE), and is sent to AppSec headers-only even with `ban`. The body reaches the backend uninspected. `Test_appsecQuery_unreadableBodyDeleteNotDropped` locks this in. (Inferred from code and test; not reproduced end-to-end.)
4. Because one `bouncerAppsecFailureAction` covers AppSec outages/500s and the unreadable body, an operator cannot let restic through without also failing open when AppSec is down.

## Decisions (made by the human in chat; do not re-litigate)

1. Bodies of unknown length are read and inspected like any other body, capped at `appsecBodyLimit`, with a **total read deadline** (time to receive the body, not an idle timeout). The deadline MUST be configurable through a new public config key (not hardcoded). Name and default value: explore decides, following existing config naming (`appsecHttpTimeoutSeconds` style) and `skill:opd-commandments`.
2. When the deadline expires the request is blocked, **independently of `bouncerAppsecFailureAction`** (fail-closed; otherwise `passthrough` + a slowly dripped body is a bypass again). Status/remediation (403 ban path vs 408): explore decides and records why.
3. gRPC and Connect get **no special case** (no Content-Type classification). Unary calls end and are inspected; client/bidirectional streams hit the deadline and are blocked. Operators exclude genuine streaming routes explicitly with `bouncerActionRules` + `bypassAppsec`.
4. `appsecBodyLimit` values `<= 0` become 10 MiB (10485760). This removes "0 = unlimited" and replaces today's validation error for negative values.
5. Bodies larger than `appsecBodyLimit`: unchanged (first N bytes inspected, remainder forwarded uninspected).
6. Consequence of 1: a DELETE body without `Content-Length` is inspected like one with it. Removing `Content-Length` no longer reduces inspection for any method we inspect.
7. `bouncerAppsecFailureAction` goes back to meaning only "AppSec failed" (unreachable, 500, unexpected status, response read error). Do NOT reintroduce `crowdsecAppsecUnreadableBodyBlock` or any bool that lets an unreadable body pass.
8. The deadline block is logged above Debug (Info or Warn), with a message that tells the operator to exclude streaming routes with `bypassAppsec`.

Principle behind all of the above: a client-controlled signal may only lead to more inspection or to a block, never to less inspection.

## Deliverables

- Code + tests (unit, and the existing e2e/mock AppSec scenarios where they assert today's drop).
- OpenSpec change updating `core_plugin_appsec_failure-action` (unreadable body no longer under the failure action) and whatever spec owns body forwarding/limits.
- README: (a) the new deadline key; (b) `appsecBodyLimit <= 0` now means 10 MiB; (c) a section explaining **how to configure applications that need streaming request bodies** (gRPC client/bidirectional streaming, Connect streaming, other long-lived uploads): `bouncerActionRules` with `bypassAppsec` scoped by host/path/method/headers (e.g. `Content-Type: ^application/grpc`), with YAML examples, and the trade-off (that route is not WAF-inspected); (d) that stripping `Content-Length` no longer skips inspection.
- PR in **English** to `master`. The PR description MUST explain the problems of the upstream proposals:
  - #407: total wait hardcoded to 1 s (slow legitimate uploads without `Content-Length` are dropped; not configurable); `appsecBodyLimit <= 0` is an immediate drop (restic breaks again for operators with 0); keeps `crowdsecAppsecUnreadableBodyBlock: false` as headers-only forwarding, i.e. a client-triggerable WAF bypass; DELETE without `Content-Length` still goes headers-only; the timed-out read runs in a goroutine that is not cancelled (verify against the diff before stating).
  - #434: the path is chosen by the client-controlled `Content-Type`; with `false` (its README's advice for gRPC) any request that claims `application/grpc` skips body inspection; no plugin-side deadline, so non-gRPC streams hang until Traefik's `readTimeout` (60 s default; forever if 0), as its own README admits; gRPC unary calls are blocked by default; HTTP/2/3 DELETE/GET without `Content-Length` become headers-only.
  - Upstream maintainer's fallback ("set crowdsecAppsecUnreadableBodyBlock: false") is the bypass in Problem 2.

## Out of scope

- Partial inspection of bodies over `appsecBodyLimit` (decision 5).
- GET/HEAD body forwarding policy (`isMethodWithForwardableBody` excludes them today; unchanged).
