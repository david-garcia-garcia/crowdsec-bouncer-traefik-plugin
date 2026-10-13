# Requirement
IssueKey: 2026-09-05-add-fail-mode

## Problem

Operators cannot name one policy for “Crowdsec LAPI is down” and one for “Crowdsec AppSec is down.” Today those outcomes are split across `updateMaxFailure` (stream/alone only), per-request live lookup that always fail-closes, and three AppSec booleans. Callers want public `AppsecFailMode` and `LapiFailMode` keys that govern behavior when AppSec or LAPI are down or unreachable. This run stops after explore because those new keys may fight the existing knobs.

Source: caller spec (`ticket/source.md`). Dest `master`.

## Current (code)

- Stream/alone: each failed stream poll increments `updateFailure`. When `updateMaxFailure != -1` and `updateFailure >= updateMaxFailure`, `isCrowdsecStreamHealthy` becomes false. Default `UpdateMaxFailure` is `0`, so the first failure marks the stream unhealthy. `-1` never marks unhealthy. Path: `pkg/crowdsecconnection/connection.go` (`handleStreamTicker`), `pkg/configuration/configuration.go` (`UpdateMaxFailure` default `0`, reject `< -1`).
- Stream/alone ServeHTTP: if `StreamHealthy()` is false, every non-trusted request is banned with `ReasonTECH`. Last cached decisions are not consulted on that branch. Path: `pkg/bouncer/bouncer.go` (`ServeHTTP` stream/alone).
- Stream startup: `StreamStartupBlock` true runs the first poll synchronously in `New`; false runs it in a goroutine and README warns all requests bypass until the first sync. Path: `pkg/crowdsecconnection/connection.go` (`startStream`), `README.md` (`StreamStartupBlock`).
- Live/none: `LiveLookup` / `queryLiveDecisions` returns `cache.BannedValue` on LAPI HTTP or parse error. ServeHTTP then remediates that request. There is no LAPI fail-open and `UpdateMaxFailure` is not used. Path: `pkg/crowdsecconnection/connection_decisions.go` (`queryLiveDecisions`), `pkg/bouncer/bouncer.go` (`LiveLookup` branch).
- Appsec mode: ServeHTTP skips LAPI/cache and only runs AppSec on the pass path. Path: `pkg/bouncer/bouncer.go` (`CrowdsecMode == AppsecMode`).
- AppSec pass path: `AppsecQuery` treats transport error or 502/503/504 as unreachable (`UnreachableBlock`); HTTP 500 as failure (`FailureBlock`); other non-200 as always-block; unreadable HTTP/2 body as `UnreadableBodyBlock`. Defaults for the three booleans are true. Path: `pkg/crowdsecconnection/connection.go` (`AppsecQuery`, `isReverseProxyError`, `AppsecPolicy`), `pkg/configuration/configuration.go` (`CrowdsecAppsecFailureBlock`, `CrowdsecAppsecUnreachableBlock`, `CrowdsecAppsecUnreadableBodyBlock`), `pkg/bouncer/bouncer.go` (`handleNextServeHTTP`).
- Redis: `RedisCacheUnreachableBlock` (default true) fail-closes cache errors other than miss; false passes the request. Path: `pkg/bouncer/bouncer.go` (`ServeHTTP` cache), `pkg/configuration/configuration.go`.
- Public docs: `README.md` documents `UpdateMaxFailure`, `StreamStartupBlock`, and the three AppSec booleans. No `AppsecFailMode` / `LapiFailMode`. `not found`.
- Specs: `openspec/specs/` has no fail-mode / LAPI-unavailability leaf. `not found`.
- Reclaim identity includes `UpdateMaxFailure` and `StreamStartupBlock`, not the AppSec block booleans. Path: `pkg/crowdsecconnection/identity.go`.

## Desired

- Public `AppsecFailMode` and `LapiFailMode` that govern how the plugin behaves when AppSec or LAPI are down or unreachable.
- Explore (this run) must map those keys onto the existing knobs (`UpdateMaxFailure`, stream unhealthy ban-all, live `BannedValue` on error, AppSec failure vs unreachable vs unreadable-body booleans, `StreamStartupBlock`) and say what fights, what folds, and what stays.
- Do not implement in this run. Caller stopped the workflow at explore.

## Affected

- `pkg/configuration/configuration.go` — public keys (later)
- `pkg/crowdsecconnection/connection.go` — stream health, `AppsecQuery`
- `pkg/crowdsecconnection/connection_decisions.go` — live LAPI error
- `pkg/bouncer/bouncer.go` — ServeHTTP fail-closed branches
- `pkg/crowdsecconnection/identity.go` — reclaim key fields (later)
- `README.md` — operator keys (later)
- `openspec/specs/` — fail-mode spec (propose, not this run)

## Out of scope

- Implementing the keys in this run.
- Changing Redis `RedisCacheUnreachableBlock` unless explore proves it is the same policy (caller named AppSec and LAPI only).
- Trusted-IP / `GetRemoteIP` technical bans (`ReasonTECH` before LAPI).
- CrowdSec LAPI protocol changes; this plugin only consumes LAPI/AppSec.

## Unknowns

- Allowed values of `AppsecFailMode` / `LapiFailMode` (fail-open / fail-closed, or more).
- Whether they replace `CrowdsecAppsecFailureBlock` + `CrowdsecAppsecUnreachableBlock` (+ maybe unreadable-body) or sit beside them.
- Whether `LapiFailMode` replaces `UpdateMaxFailure` or only names the action after the counter trips.
- Whether live mode must grow a retry/threshold like stream, or stay per-request.
- What official CrowdSec bouncers do on LAPI/AppSec unavailability (research in flight).

## Tensions

- `UpdateMaxFailure` is a counter-to-unhealthy gate in stream/alone, not a fail-open/fail-closed enum. `LapiFailMode` that “governs HOW” on down/unreachable overlaps that gate and the ServeHTTP ban-all that follows it.
- Live LAPI errors already fail-close with no counter. A single `LapiFailMode` cannot mean the same thing in live vs stream without an explicit decision.
- AppSec already splits 500 vs unreachable vs unreadable-body into three booleans. One `AppsecFailMode` collapses or fights those.
- `StreamStartupBlock` is a startup race (serve before first sync), not LAPI-down. Easy to mix into fail-mode.
- AppSec block booleans are per-router on `Bouncer`; `UpdateMaxFailure` is on `CrowdsecConnection` identity. A new fail-mode key must pick an owner or split.
