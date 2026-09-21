# Requirement
IssueKey: 2026-09-21-appsec-cancelled-body-ban

## Problem
With AppSec enabled and default body buffering, a client that disconnects mid-body (HTTP/2 CANCEL, etc.) makes `io.ReadAll` fail while copying the request body; the plugin treats that as an AppSec query failure and responds with a 403 ban (`ReasonAPPSEC`) even though AppSec never evaluated the request. `bouncerAppsecFailureAction: passthrough` does not cover this path, and bans are hard to see at default log level.

Upstream report: [maxlerebourg/crowdsec-bouncer-traefik-plugin#395](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/395).

## Current (code)
- `pkg/appsec/query.go` `newAppsecBodyRequest`: when the body is readable and the method forwards a body, buffers via `io.TeeReader` + `io.ReadAll` (with `LimitReader` when `appsecBodyLimit > 0`); any read error returns `fmt.Errorf("appsecQuery:GetBody %w", err)` without `resultForFailureAction` (`pkg/appsec/query.go`).
- `pkg/bouncer/bouncer.go` `applyAppsecServeHTTP`: any non-`ErrFailureCaptcha` error from `appsecClient.Query` logs at DEBUG and calls `handleBanServeHTTP` with `ReasonAPPSEC` (`pkg/bouncer/bouncer.go`).
- `pkg/appsec/query.go` `isBodyUnreadable`: only the HTTP/2+ no-`Content-Length` case; mid-stream read errors during buffering are not classified as client disconnect (`pkg/appsec/query.go`).
- `pkg/configuration/configuration.go`: default `AppsecBodyLimit` is `10485760`; `BouncerAppsecFailureAction` gates unreachable, AppSec 500, and `appsecQuery:unreadableBody dropped` via `resultForFailureAction`, not the `GetBody` error path (`pkg/configuration/configuration.go`, `pkg/appsec/query.go` `Query` / `newAppsecBodyRequest`).
- `pkg/appsec/zzz_query_test.go`: covers streaming, unreadable-body, and failure-action paths; no test simulating a client-cancelled body read during buffering.
- On `origin/master` at `e4b1be2`, the same `GetBody` → ban wiring is present; presence on this fork is not yet proven by an automated test in-tree.

## Desired
- Do not treat a **client-side** body read cancellation/disconnect as an AppSec ban (pass-through or stop without 403), consistent with the spirit of unreadable-body handling; distinguish client cancel (`context.Canceled`, HTTP/2 `CANCEL`, `io.ErrUnexpectedEOF`, etc.) from genuine read faults if fixing behavior.
- **Fork scope:** determine whether #395 affects this fork on `master`; add an automated test that **proves** the bug is present or absent on this tree (no fix required in prepare).
- **Delivery:** upstream issue URL must appear on the delivery card (reporting only, not product code).

## Affected
- `pkg/appsec/query.go` (`newAppsecBodyRequest`, `isBodyUnreadable`, error classification).
- `pkg/bouncer/bouncer.go` (`applyAppsecServeHTTP`).
- `pkg/configuration/configuration.go` (only if a new fail-open knob or FailureAction extension is chosen later).
- `pkg/appsec/zzz_query_test.go` (regression / presence test for cancelled body read).

## Out of scope
- Changing default `appsecBodyLimit`, log levels, or metrics/LAPI reporting beyond what a fix to the ban path requires.
- Live HTTP/2 reproduction in e2e unless explore chooses it; upstream PR to maxlerebourg (this run grounds a fork investigation/fix).
- New product features not asked by #395 or the fork test/card asks above.

## Unknowns
- Preferred fix shape on upstream (silent pass-through vs extending `BouncerAppsecFailureAction` vs new knob) — reporter offered either.
- Whether `handleBanServeHTTP` should run at all when the client is already gone.
- Exact error types Traefik/net/http surface for HTTP/2 stream cancel in this plugin’s Go version.
- Blast radius for LAPI dropped-request metrics if behavior changes.

## Tensions
- #395 describes three legacy `*Block` bools; this fork on `master` uses `bouncerAppsecFailureAction` instead, but **mid-stream `GetBody` failures still always ban** — passthrough on that path is not available today.
- Fork work adds a **test-or-absence proof** and **card URL** beyond upstream issue text.
- Existing `explore.md` on this branch was written against the wrong dest layout (root `bouncer.go` / `main`); explore should re-read this requirement before propose/implement.
