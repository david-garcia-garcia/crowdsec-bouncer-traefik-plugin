## Context

`isBodyUnreadable` already detects HTTP/2+ requests with a body and `ContentLength < 0` (gRPC streams). Hang-on-`io.ReadAll` is gone. `newAppsecBodyRequest` still returns `appsecQuery:unreadableBody dropped` unless `CrowdsecAppsecFailureAction` is `passthrough`. Default is `ban`, so AppSec-enabled routers 403 NetBird `ConnectStream` with no LAPI decision (upstream #323). lua-cs-bouncer `APPSEC_DROP_UNREADABLE_BODY` defaults false (headers-only). This plugin’s fail-mode change folded the old unreadable-body bool into the failure action; that lump is the remaining bug.

## Goals / Non-Goals

**Goals:**
- Headers-only AppSec GET for every unreadable HTTP/2+ body, including default `ban`.
- Keep `CrowdsecAppsecFailureAction` default `ban` for 500 and unreachable.
- Reuse `Query`’s existing `ip` argument (`GetRemoteIP`). Do not parse forwarded headers in AppSec.

**Non-Goals:**
- Changing `CrowdsecAppsecFailureAction` or `CrowdsecLapiFailureAction` defaults to CrowdSec spec passthrough.
- Re-adding `crowdsecAppsecUnreadableBodyBlock` / `APPSEC_DROP_UNREADABLE_BODY`.
- NetBird or Traefik e2e.
- AppSec-disabled path, WebSocket, LAPI decision lookup.

## Decisions

1. **Always headers-only GET when `isBodyUnreadable`.** Remove the `isMethodWithBody && action != passthrough` drop branch in `newAppsecBodyRequest`. Same path as today’s GET exemption and as lua default false. Alternative: flip enum default to `passthrough` — rejected; that fail-opens AppSec 500/unreachable as a drive-by (prior fail-mode explore kept `ban`).

2. **Failure action still applies to the headers-only GET.** 500 / unreachable / `captcha` on that call stay on `resultForFailureAction`. Unreadable body is not itself a failure.

3. **No new public key.** Opt-in drop is a follow-up (`issues.md`), not this change.

4. **Tests:** `Test_appsecQuery_dropUnreadableBody` MUST assert Query succeeds under `FailureActionBan` and that AppSec received GET (no hang). Keep `Test_appsecQuery_streamingDoesNotBlock`.

## Risks / Trade-offs

- [WAF cannot see gRPC bodies] → same as lua default; headers/IP/URI/verb still go to AppSec. Official nginx docs warn this is a body-inspection gap; ticket requires pass-through.
- [Operators who used default `ban` as an implicit gRPC block] → that was the #323 bug; document in README that unreadable bodies are headers-only.

## Migration Plan

Plugin version bump. No YAML migration. Rollback: previous tag restores drop-on-ban for unreadable POST.
