## Context

This branch already sends a headers-only AppSec GET when `isBodyUnreadable` (HTTP/2+, body present, `ContentLength < 0`). That closes #323 under default `crowdsecAppsecFailureAction: ban`. DestBranch drops those POSTs because fail-mode folded `CrowdsecAppsecUnreadableBodyBlock` into that enum. lua-cs-bouncer keeps `APPSEC_DROP_UNREADABLE_BODY` (default false) independent of `appsec_failure_action`. The human asked to restore the Traefik bool on this PR.

## Goals / Non-Goals

**Goals:**
- Public `crowdsecAppsecUnreadableBodyBlock`, default false (headers-only GET).
- True drops POST/PUT/PATCH/DELETE unreadable streams without calling AppSec; GET/HEAD stay headers-only.
- Independent of `CrowdsecAppsecFailureAction`. Reuse `Query`’s existing `ip` (`GetRemoteIP`).

**Non-Goals:**
- Changing `CrowdsecAppsecFailureAction` default.
- Re-adding `crowdsecAppsecFailureBlock` or `crowdsecAppsecUnreachableBlock`.
- Copying Traefik shipped default true (would re-open #323).
- NetBird e2e. AppSec-disabled path, WebSocket, LAPI lookup.

## Decisions

1. **Bool on `Config` and `appsec.Policy`, not on reclaimed `appsec.Client`.** Same owner as `FailureAction` (per-router). `New()` sets false. `omitempty` matches other bools (`CrowdsecAppsecEnabled`).

2. **Drop uses `isMethodWithBody` from DestBranch** (POST, PUT, PATCH, DELETE). Do not invent a second method set. True + GET → headers-only GET (lua GET exemption).

3. **Drop error is `appsecQuery:unreadableBody dropped`.** Bouncer already maps Query error (except captcha) to `handleBanServeHTTP` / `ReasonAPPSEC`. Do not consult `FailureAction` on this branch.

4. **Pass `Policy` into `newAppsecBodyRequest`.** `Query` already has `pol`; the unreadable branch must read `pol.UnreadableBodyBlock`.

5. **Tests.** Default-false streaming POST under `FailureActionBan` still GET + no error. True + POST returns the drop error and AppSec is not called. True + GET still queries. True + `FailureActionPassthrough` still drops POST.

## Risks / Trade-offs

- [WAF cannot see gRPC bodies at default false] → same as lua default; headers/IP/URI/verb still go to AppSec. Operators set true to drop.
- [Traefik upstream defaults true] → rejected; that default is the #323 bug. Document false in README.

## Migration Plan

New YAML key, default false. No migration. Operators who want DestBranch’s implicit drop set `crowdsecAppsecUnreadableBodyBlock: true`. Rollback: previous tag without the key keeps headers-only on this branch’s parent; DestBranch still drops via `ban`.
