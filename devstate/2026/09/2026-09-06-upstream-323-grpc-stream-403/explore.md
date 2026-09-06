# Explore
IssueKey: 2026-09-06-upstream-323-grpc-stream-403

Measured (this branch, after headers-only apply): `go test ./pkg/appsec/ -count=1 -run Test_isBodyUnreadable|Test_appsecQuery_streamingDoesNotBlock|Test_appsecQuery_unreadableBodyQueriesHeadersOnlyUnderBan|Test_appsecQuery_unreadableBodyGetNotDropped` passed (0.960s). `newAppsecBodyRequest` always builds a headers-only GET when `isBodyUnreadable` (`pkg/appsec/query.go:132-135`). There is no `CrowdsecAppsecUnreadableBodyBlock` on `Config` (`pkg/configuration/configuration.go`). DestBranch (`origin/master`) still folds unreadable-body drop into `CrowdsecAppsecFailureAction` default `ban`.

RETHINK (human, 2026-09-06): introduce public knob `CrowdsecAppsecUnreadableBodyBlock` on this same PR. Prior explore left that as `issues.md` note large; the human overrode Bound the ask.

## Concepts

```
  HTTP/2+ POST, Content-Length < 0, body open (gRPC ConnectStream)
                         │
                         ▼
              isBodyUnreadable = true
                         │
         ┌───────────────┴───────────────────────────────┐
         │ UnreadableBodyBlock false (default)           │
         │   headers-only GET to AppSec                  │
         │   original stream untouched                   │
         │   FailureAction applies to that GET           │
         │   500/unreachable only                        │
         ├───────────────────────────────────────────────┤
         │ UnreadableBodyBlock true                      │
         │   method with body → drop                     │
         │   appsecQuery:unreadableBody dropped          │
         │   no AppSec call; bouncer 403 ReasonAPPSEC    │
         │   GET/HEAD still headers-only GET             │
         └───────────────────────────────────────────────┘
```

`isBodyUnreadable` (`pkg/appsec/query.go`) matches lua-cs-bouncer: HTTP/2+ with a body and `ContentLength < 0`. Hang-on-`io.ReadAll` is already gone. This rethink does not change that detector.

lua `APPSEC_DROP_UNREADABLE_BODY` (default **false**) is independent of `appsec_failure_action`. Traefik upstream still ships `CrowdsecAppsecUnreadableBodyBlock: true`. This fork's fail-mode change removed the bool and lumped drop into default `ban`; that lump is the #323 403. Headers-only on this branch already matches lua default false. The missing piece is lua `true`: operators who want fail-closed on uninspectable gRPC bodies.

Client IP stays `pkg/ip.GetRemoteIP` → `Query(ip, …)`. This change does not reconstruct identity.

## Decisions

- Do not change `CrowdsecAppsecFailureAction` default (`ban`). This ticket is unreadable-body policy, not AppSec-down posture.
- Re-add `CrowdsecAppsecUnreadableBodyBlock` (`json:"crowdsecAppsecUnreadableBodyBlock,omitempty"`). Default **false** in `configuration.New()` (lua default, #323 pass-through). Do not copy Traefik shipped default `true`.
- The bool is independent of `CrowdsecAppsecFailureAction`. `true` drops a method-with-body unreadable stream even when failure action is `passthrough`. `false` headers-only GETs even when failure action is `ban`.
- When the bool is true, GET/HEAD (no body expected) still send headers-only GET — lua GET exemption / Traefik `isMethodWithBody`. Restore that helper next to `isBodyUnreadable`.
- Put the bool on `appsec.Policy` (per-router, same owner as `FailureAction`). Pass it into `newAppsecBodyRequest`. Do not store it on the reclaimed `appsec.Client`.
- Drop path returns `appsecQuery:unreadableBody dropped` (same error DestBranch used). Bouncer already maps Query error (except captcha) to `handleBanServeHTTP` / `ReasonAPPSEC`.
- Live spec `core_plugin_appsec_failure-action` currently forbids the bool and says unreadable body is always headers-only. Propose must retract those two claims and add the knob contract. FindSpecHost decides fold vs new leaf.
- Do not re-add `crowdsecAppsecFailureBlock` or `crowdsecAppsecUnreachableBlock`.
- Do not change LAPI lookup, AppSec-disabled path, or WebSocket handling.

## Open questions

- Q: Exact upstream #332 default on maxlerebourg master — passthrough/headers-only or still drop?
  Decision: resolved — PR #332 text defaulted drop-unreadable to false (headers-only). Shipped `configuration.New()` still sets `CrowdsecAppsecUnreadableBodyBlock: true`. Issue comments (bhz0u, Aterfax, mathieuHa, maxlerebourg) confirm operators must set the bool false; README was later aligned to `true`. This fork defaults the restored bool to **false** so #323 stays closed.
  By: explore

- Q: Is the fix a default-only flip of `CrowdsecAppsecFailureAction` to `passthrough`, or always headers-only GET for unreadable streaming POST regardless of `ban`?
  Decision: resolved — default path is headers-only GET (`UnreadableBodyBlock` false). Failure action stays `ban` for 500/unreachable. Human RETHINK: operators may set `crowdsecAppsecUnreadableBodyBlock: true` to drop methods with an unreadable body.
  By: explore

- Q: Who already owns the client address for the AppSec query?
  Decision: resolved — `pkg/ip.GetRemoteIP` on `clientRequest.remoteIP`; `appsec.Client.Query` takes that IP. Reuse it. Do not parse `X-Real-Ip` in AppSec.
  By: explore

- Q: Should `crowdsecAppsecFailureAction: passthrough` override `crowdsecAppsecUnreadableBodyBlock: true`?
  Decision: resolved — no. Independent knobs, matching lua `APPSEC_DROP_UNREADABLE_BODY` vs `appsec_failure_action`. Passthrough does not mean “never drop an unreadable stream.”
  By: explore

- Q: Default `CrowdsecAppsecUnreadableBodyBlock` true (Traefik shipped) or false (lua / this ticket)?
  Decision: resolved — false. True would re-open #323 under default operator YAML. Official CrowdSec nginx docs default false and warn that WAF may not see the body; operators who want drop set true.
  By: explore
