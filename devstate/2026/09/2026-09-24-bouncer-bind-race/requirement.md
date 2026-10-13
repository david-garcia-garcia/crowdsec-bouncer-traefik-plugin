# Requirement
IssueKey: 2026-09-24-bouncer-bind-race

## Problem
`storeBinding` mutates `Box.Value` in place after the first publish. Concurrent `ServeHTTP` paths `Unbox` that same `*reclaim.Box` while `ReceiveLAPI` / `ReceiveAppSec` / `ReceiveCaptcha` write `boxed.Value` from `reclaim.Watch`. That races: a torn `any` can panic the request, or a request can see a nil/stale client and take the failure action or the wrong LAPI mode.

## Current (code)
- `pkg/bouncer/bouncer.go` `storeBinding`: on a later publish, when `dest.Load()` already holds `*reclaim.Box`, assigns `boxed.Value = value` and returns without `Store`.
- `pkg/bouncer/bouncer.go` `ReceiveLAPI` / `ReceiveAppSec` / `ReceiveCaptcha`: call `storeBinding` with `notice.Value` from `reclaim.Published` (watch callbacks).
- `pkg/reclaim/default.go` `Unbox`: `Load`s the `*Box` then returns `boxed.Value` (plain `any`).
- `pkg/bouncer/bouncer.go` `loadedLAPI` / `loadedAppSec` / `loadedCaptcha`: call `reclaim.Unbox` on the bound `atomic.Value` fields.
- `pkg/bouncer/bouncer.go` `ServeHTTP`: uses those loaded clients on the request path; no recover around the handler.
- Contract: `openspec/specs/core_plugin_middleware_bouncer/spec.md` requirement "Bouncer binds clients through atomic late bind" — Load only; nil client must not panic; mode follows the published client.
- Yaegi: `atomic.Value` concrete type must stay `*reclaim.Box` (`pkg/reclaim/default.go` Box comment; vendor `traefik-middleware-utilities/reclaim` `Box` struct).

## Desired
On every bind update, `storeBinding` publishes a new immutable snapshot: `dest.Store(&reclaim.Box{Value: value})`. Do not mutate `Box.Value` in place. Keep the stored concrete type `*reclaim.Box`. Behavior for nil clients and LAPI mode must match the late-bind contract (Load only; no panic on nil; mode from the published client).

## Affected
- `pkg/bouncer/bouncer.go` (`storeBinding` and the three Receive* callers that feed it)

## Out of scope
- Findings 2 and 3 from review-findings.md
- Unrelated bouncer policy refactors
- Changing reclaim Watch / Unbox API shape beyond what Finding 1 requires
- Editing review-findings.md in the main checkout

## Unknowns
- Whether any other in-tree watcher still mutates `Box.Value` in place (explore)
- Exact race window under Yaegi vs native Go (explore / measure)

## Tensions
- None vs ticket: the ask names the fix shape (`Store` a new Box each update) and forbids Findings 2/3 and unrelated policy work.
