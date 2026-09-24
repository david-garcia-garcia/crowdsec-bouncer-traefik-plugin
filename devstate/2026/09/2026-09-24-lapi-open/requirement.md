# Requirement
IssueKey: 2026-09-24-lapi-open

## Problem
The Traefik constructor must pick `lapi.OpenStream` or `lapi.OpenLive` from `LapiMode`. That split is not a consumer concern: both functions do the same reclaim Open, and the only extra line in `OpenStream` already no-ops unless mode is stream or alone.

## Current (code)
- `openOwnedLeg` branches on `LapiMode`: stream or alone calls `lapi.OpenStream`, otherwise `lapi.OpenLive`: `plugin.go`
- `OpenStream` and `OpenLive` both open the decision store, reclaim on `OwnershipKey`, `New`, hooks, and `bindIdentity`: `pkg/lapi/session.go`
- The only extra line in `OpenStream` is `noteStreamOwner`; that helper returns unless `LapiMode` is stream or alone: `pkg/lapi/session.go`
- `LapiMode` is already on the `Config` that `New` reads (`crowdsecMode`, stream ticker gate): `pkg/lapi/client.go`, `pkg/lapi/client_stream.go`
- AppSec and captcha each expose a single `Open`: `pkg/appsec/session.go`, `pkg/captcha/session.go`

## Desired
One `lapi.Open` that `plugin.go` calls the same way it calls `appsec.Open` and `captcha.Open`. The stream-collision log stays inside `lapi`. Do not change LAPI mode behavior.

## Affected
- `plugin.go` — `openOwnedLeg` LAPI branch
- `pkg/lapi/session.go` — `OpenStream`, `OpenLive`, `noteStreamOwner`

## Out of scope
- Changing stream, live, none, or alone runtime (poll, live lookup, metrics, CAPI token).
- Changing `noteStreamOwner` collision semantics or the warn text.
- Changing AppSec or captcha `Open`.
- New public config keys or `LapiMode` validation.

## Unknowns
- Whether `OpenStream` / `OpenLive` stay as aliases or are removed (the ticket asks for one `Open`; test call sites still name the split).
- Blast radius of renaming the test entry points under `pkg/lapi/`.
- Whether live/none walking through `noteStreamOwner` (early return) has any process-global side effect besides the mode gate.

## Tensions
- Ticket: the consumer split makes no sense. Dest: `plugin.go` is the only production caller; tests still choose `OpenStream` vs `OpenLive` by scenario (`pkg/lapi/zzz_*.go`). Desired is still one `Open`.
- Ticket: both functions do the same reclaim Open. Dest matches, except `noteStreamOwner` on `OpenStream`, which already no-ops outside stream/alone.
