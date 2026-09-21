# Requirement
IssueKey: 2026-09-21-appsec-cancelled-body-ban

## Problem
With AppSec enabled and default body buffering, a client that disconnects mid-body (HTTP/2 CANCEL, etc.) causes `io.ReadAll` to fail; the plugin treats that as an AppSec failure and responds with a 403 ban (`ReasonAPPSEC`) even though AppSec never evaluated the request. Existing fail-open flags do not cover this path, and bans are hard to see at default log level.

Upstream report: [maxlerebourg/crowdsec-bouncer-traefik-plugin#395](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/395).

## Current (code)
- `bouncer.go` `appsecQuery`: when `appsecBodyLimit > 0` and `Body != nil`, buffers via `io.ReadAll`; any read error returns `appsecQuery:GetBody %w` (`bouncer.go`).
- `bouncer.go` `handleNextServeHTTP`: any non-nil `appsecQuery` error triggers `handleBanServeHTTP` with `ReasonAPPSEC` (`bouncer.go`).
- `bouncer.go` `isBodyUnreadable` / unreadable-body branch: only skips or blocks the no-`Content-Length` HTTP/2+ case; mid-stream read errors on buffered bodies are not classified as client disconnect (`bouncer.go`).
- `pkg/configuration/configuration.go`: defaults `CrowdsecAppsecBodyLimit` to `10485760`; `CrowdsecAppsecFailureBlock`, `CrowdsecAppsecUnreachableBlock`, and `CrowdsecAppsecUnreadableBodyBlock` do not gate the `GetBody` error path (`configuration.go`, wired in `bouncer.go` `New`).
- `bouncer_test.go`: covers streaming/unreadable-body regressions (#323, #351); no test for client-cancelled body read during buffering.
- Issue reporter confirms behavior on upstream `main` at `710e888`; this fork’s `origin/main` is `23ce76d3` with the same `appsecQuery` / `handleNextServeHTTP` pattern (not yet proven by an automated test in this fork).

## Desired
- Do not treat a **client-side** body read cancellation/disconnect as an AppSec ban (pass-through or stop without 403), consistent with the spirit of unreadable-body handling; distinguish client cancel (`context.Canceled`, HTTP/2 `CANCEL`, `io.ErrUnexpectedEOF`, etc.) from genuine read faults if fixing upstream behavior.
- **Fork scope:** determine whether this bug affects this fork’s code as checked out on `destBranch`; add an automated test that **proves** the bug is present or absent on this tree (no fix required in prepare).
- **Delivery:** upstream issue URL must appear on the delivery card (reporting only, not product code).

## Affected
- `bouncer.go` (`appsecQuery`, `handleNextServeHTTP`, possibly error classification helpers).
- `pkg/configuration/configuration.go` (only if a new fail-open knob is chosen later; ticket allows pass-through without a new option).
- `bouncer_test.go` (regression / presence test for cancelled body read).

## Out of scope
- Changing default `crowdsecAppsecBodyLimit`, log levels, or metrics/LAPI reporting beyond what a fix to the ban path requires.
- Live HTTP/2 reproduction in e2e unless explore chooses it; full upstream PR to maxlerebourg (this run grounds a fork investigation/fix).
- New product features not asked by #395 or the fork test/card asks above.

## Unknowns
- Preferred fix shape on upstream (silent pass-through vs new config flag) — reporter offered either.
- Whether `handleBanServeHTTP` should run at all when the client is already gone.
- Exact error types Traefik/net/http surface for HTTP/2 stream cancel in this plugin’s Go version.
- Blast radius for LAPI dropped-request metrics if behavior changes.

## Tensions
- None between ticket and code; fork work adds a **test-or-absence proof** and **card URL** beyond upstream issue text.
