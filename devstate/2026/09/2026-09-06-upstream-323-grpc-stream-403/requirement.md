# Requirement
IssueKey: 2026-09-06-upstream-323-grpc-stream-403

## Problem
With AppSec enabled and default config, long-lived gRPC streaming POSTs (HTTP/2, `Content-Length: -1`, e.g. NetBird `/signalexchange.SignalExchange/ConnectStream`) are silently forbidden by the plugin (`DownstreamStatus: 403`, `OriginStatus: 0`) even when LAPI has no ban decision for the client IP. Upstream #323; assessment binds `recommended-action: fix`.

## Current (code)
- `pkg/appsec/query.go:77-79` — `isBodyUnreadable` detects HTTP/2+ POST with body and `ContentLength < 0` (streaming gRPC shape).
- `pkg/appsec/query.go:146-148` — when unreadable and method has body and failure action is not `passthrough`, `newAppsecBodyRequest` returns `appsecQuery:unreadableBody dropped` without calling AppSec.
- `pkg/configuration/configuration.go:167` — `CrowdsecAppsecFailureAction` defaults to `FailureActionBan` (`ban`).
- `pkg/bouncer/bouncer.go:306-314` — AppSec query error (except captcha) triggers `handleBanServeHTTP` → client 403 with `ReasonAPPSEC`.
- `pkg/appsec/query_test.go:69-90` — `Test_appsecQuery_streamingDoesNotBlock` passes with `FailureActionPassthrough` (no hang regression).
- `pkg/appsec/query_test.go:93-115` — `Test_appsecQuery_dropUnreadableBody` expects error under default `ban` policy.
- `openspec/specs/core_plugin_appsec_failure-action/spec.md:33-35` — spec scenario: unreadable body + `ban` drops request without calling origin.

## Desired
- gRPC streaming connections pass through the bouncer without plugin-forbidden 403 when no CrowdSec decision exists for the client IP (ticket expected behavior).
- Fix product default and/or unreadable-body handling so AppSec-enabled deployments match that outcome under default operator config (assessment: align with upstream post-#332 passthrough default, or equivalent behavior that still queries AppSec headers-only for streams).

## Affected
- `pkg/appsec/query.go` (unreadable-body branch)
- `pkg/configuration/configuration.go` (default `crowdsecAppsecFailureAction`)
- `pkg/bouncer/bouncer.go` (AppSec error → ban path for unreadable body)
- `pkg/appsec/query_test.go` (streaming / unreadable-body tests)
- Possibly `openspec/specs/core_plugin_appsec_failure-action/spec.md` if default or unreadable-body contract changes

## Out of scope
- v1.6.0 hang on `io.ReadAll` for streaming bodies (already fixed via `isBodyUnreadable`).
- LAPI decision lookup when no AppSec path runs (reporters had no decisions).
- Non-AppSec-only deployments (`crowdsecAppsecEnabled: false`).
- Full NetBird or Traefik e2e reproduction in this change.
- WebSocket or standard HTTPS paths (reported working).

## Unknowns
- Exact upstream #332 default change on maxlerebourg repo — assessment cites passthrough default; not verified in this tree.
- Whether fix is default-only vs. always headers-only GET to AppSec for unreadable streaming POST regardless of `ban` setting.

## Tensions
- Ticket: pass-through with no LAPI decision vs. current spec + tests: `ban` on unreadable body drops before AppSec and origin.
- Assessment says symptom matches default `ban`; upstream reportedly moved default to `passthrough` after #332 — fork still defaults `ban`.
- `Test_appsecQuery_dropUnreadableBody` encodes drop-on-ban; changing default or unreadable-body semantics requires updating spec/tests together.
