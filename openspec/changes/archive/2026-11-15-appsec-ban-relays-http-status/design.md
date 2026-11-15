## Context

See proposal.md for why. `applyAppsecServeHTTP` routes `appsec.ActionBan` to `handleBanStatusServeHTTP` with the status from `appsecBanStatusCode`, which today returns 429 for `http_status` 429 and `remediationStatusCode` otherwise. CrowdSec `GenerateResponse` fills `http_status` on every `ban` with `UserHTTPResponseCode`, else `UserBlockedHTTPCode` (default 403) (`knowledge/research/ext_crowdsec_appsec_protocol/notes.md`).

## Goals / Non-Goals

**Goals:**
- AppSec ban → client status is its `http_status` when from 200 to 599, as upstream #436.
- Unit tests that fail on master for a custom code, the default 403 over a configured status, and both range edges.

**Non-Goals:**
- Changing the status of LAPI bans, failure actions, action rules, or the captcha downgrade.
- Relaying `http_status` for `captcha` (the bouncer renders its own captcha).
- A config switch to restore the 429-only behavior.

## Decisions

- Relay 200–599, as upstream. Alternative: 400–599 — rejected by the owner to keep parity with upstream. Alternative: relay only codes other than 403 so `bouncerRemediationStatusCode` still applies to the default — rejected; it cannot tell the default from `SetReturnCode(403)` and diverges from upstream.
- This reverses the "Only 429 is honoured" decision of `2026-11-14-appsec-ban-keeps-429`. The README now points operators to `user_blocked_http_code` to change the AppSec ban status.
- Skip the template body for 204 and 304 in `handleBanStatusServeHTTP`. Without it, `banTemplate.Execute` fails with `http.ErrBodyNotAllowed` and logs a WARN on every such request. Applies to every ban path, including a `bouncerRemediationStatusCode` of 204 or 304.
- Header stays `ban:appsec` for every relayed code.

## Risks / Trade-offs

- [Operator set `bouncerRemediationStatusCode` deliberately] → AppSec bans switch to CrowdSec's 403 (or `user_blocked_http_code`); announced as a behavior change in the release notes.
- [`SetReturnCode(200)` or a 3xx] → the ban page is served with that status, as upstream; a 3xx carries no `Location`. Operator choice in CrowdSec.

## Migration Plan

- No config or stored-data change. Operators who relied on `bouncerRemediationStatusCode` for AppSec bans set `user_blocked_http_code` in the CrowdSec appsec-config. Rollback restores the 429-only rule.
