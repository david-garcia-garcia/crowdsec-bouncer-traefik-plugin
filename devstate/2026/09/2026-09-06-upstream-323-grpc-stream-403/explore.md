# Explore
IssueKey: 2026-09-06-upstream-323-grpc-stream-403

Measured: `go test ./pkg/appsec/ -run Test_appsecQuery_streamingDoesNotBlock|Test_appsecQuery_dropUnreadableBody|Test_appsecQuery_unreadableBodyGetNotDropped` passed (0.867s). Hang regression is gone. `Test_appsecQuery_dropUnreadableBody` still expects an error under `FailureActionBan` — that error is the ticket 403 (`pkg/bouncer/bouncer.go` `applyAppsecServeHTTP` → `handleBanServeHTTP`). Not a NetBird e2e; unit path matches the reported AppSec-enabled symptom.

## Concepts

```
  HTTP/2 POST, Content-Length < 0, body open (gRPC ConnectStream)
                         │
                         ▼
              isBodyUnreadable = true
                         │
         ┌───────────────┴───────────────┐
         │ DestBranch today              │  Ticket expected
         │                               │
         │ ban (default) → drop,         │  no CrowdSec decision
         │   no AppSec call,             │  → pass to origin
         │   bouncer 403                 │  (headers-only AppSec OK)
         │ passthrough → GET headers     │
         └───────────────────────────────┘
```

`isBodyUnreadable` (`pkg/appsec/query.go`) already matches lua-cs-bouncer: HTTP/2+ with a body and `ContentLength < 0`. The hang from v1.6.0 `io.ReadAll` is fixed. The remaining bug is policy: `newAppsecBodyRequest` treats an unreadable **method-with-body** as an AppSec **failure** unless `CrowdsecAppsecFailureAction` is `passthrough`. Default is `ban` (`pkg/configuration/configuration.go` `New`). `resultForFailureActionErr` then becomes `appsecQuery:unreadableBody dropped`, and the bouncer remediates as 403 with `ReasonAPPSEC` — no LAPI decision, no AppSec listener call.

Prior fail-mode change (`2026-09-05-add-fail-mode`) folded `CrowdsecAppsecUnreadableBodyBlock` into `CrowdsecAppsecFailureAction` and kept default `ban` so dest does not silently fail-open on AppSec 500/unreachable. That lump is why default AppSec deployments still match #323.

Upstream #332 (PR) intended headers-only by default (`CrowdsecAppsecDropUnreadableBody` false, lua `APPSEC_DROP_UNREADABLE_BODY`). Shipped master still defaults `CrowdsecAppsecUnreadableBodyBlock: true` for backward compatibility; reporters still had to set it false. Assessment “passthrough default after #332” is the PR intent, not the shipped Traefik default.

lua-cs-bouncer (upstream collaborator write-up on #323): refuse to buffer HTTP/2+ with no Content-Length; default **false** → headers-only AppSec; **true** → drop. Official CrowdSec `appsec_failure_action` covers timeout/500/401, not “body cannot be copied.” Unreadable stream is not AppSec-down.

Client IP stays `pkg/ip.GetRemoteIP` → `Query(ip, …)`. This change does not reconstruct identity.

## Decisions

- Do not change `CrowdsecAppsecFailureAction` default (`ban`). Prior human/explore on fail-mode: do not flip fail-closed 500/unreachable to CrowdSec spec passthrough without an explicit yes. This ticket is the gRPC 403, not AppSec-down posture.
- Split unreadable body out of failure-action drop. Always send headers-only GET to AppSec when `isBodyUnreadable` (same as today’s GET and as `passthrough`). `CrowdsecAppsecFailureAction` still applies to that GET’s 500/unreachable/`captcha`.
- Do not re-add `CrowdsecAppsecUnreadableBodyBlock`. Bound the ask. Opt-in drop is a follow-up (`issues.md`).
- Do not change LAPI lookup, AppSec-disabled path, or WebSocket handling.
- Spec `core_plugin_appsec_failure-action` must drop the “unreadable body + ban → drop without origin” scenario and keep 500/unreachable as today.

## Open questions

- Q: Exact upstream #332 default on maxlerebourg master — passthrough/headers-only or still drop?
  Decision: resolved — PR #332 text defaulted drop-unreadable to false (headers-only). Shipped `configuration.New()` still sets `CrowdsecAppsecUnreadableBodyBlock: true`. Issue comments (bhz0u, Aterfax, mathieuHa, maxlerebourg) confirm operators must set the bool false; README was later aligned to `true`. Do not copy the shipped Traefik default; it leaves #323 open.
  By: explore

- Q: Is the fix a default-only flip of `CrowdsecAppsecFailureAction` to `passthrough`, or always headers-only GET for unreadable streaming POST regardless of `ban`?
  Decision: assumed — always headers-only GET for `isBodyUnreadable`; keep `CrowdsecAppsecFailureAction` default `ban` for 500/unreachable. Unreadable body is not AppSec-down. Changing the enum default would fail-open AppSec 500 as a drive-by.
  By: explore

- Q: Who already owns the client address for the AppSec query?
  Decision: resolved — `pkg/ip.GetRemoteIP` on `clientRequest.remoteIP`; `appsec.Client.Query` takes that IP. Reuse it. Do not parse `X-Real-Ip` in AppSec.
  By: explore
