# Explore

## Concepts

Upstream report: [maxlerebourg/crowdsec-bouncer-traefik-plugin#395](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/395). Fork PR [#133](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/133) tracks investigation/fix on this tree.

```
Client POST (HTTP/2, Content-Length set)
        │
        ▼
Bouncer.ServeHTTP → … → handleNextServeHTTP
        │
        ├─ appsecEnabled ──► appsecQuery
        │                         │
        │                    isBodyUnreadable? ──no (CL=1000, Proto≥2)
        │                         │
        │                    appsecBodyLimit>0 ──► io.ReadAll(TeeReader(LimitReader(Body)))
        │                         │
        │                    err != nil ──► "appsecQuery:GetBody %w"
        │
        └─ err != nil ──► handleBanServeHTTP(ReasonAPPSEC) ──► 403
```

| Unit | Path | Job |
|------|------|-----|
| AppSec gate | `bouncer.go` `handleNextServeHTTP` | Any `appsecQuery` error → ban with `configuration.ReasonAPPSEC` |
| Body buffer | `bouncer.go` `appsecQuery` | Default limit 10MiB via `io.ReadAll`; no fail-open on read error |
| Unreadable skip | `bouncer.go` `isBodyUnreadable` | HTTP/2+ **without** Content-Length only; mid-read errors not covered |
| Config flags | `pkg/configuration/configuration.go` + `bouncer.go` `New` | `CrowdsecAppsecFailureBlock`, `Unreachable`, `UnreadableBodyBlock` — none gate `GetBody` errors |
| Tests | `bouncer_test.go` | Streaming/unreadable (#323, #351); no cancel-mid-read case |

Call sites for `appsecQuery` error → ban: **1** production path (`handleNextServeHTTP` in `bouncer.go`), searched `*.go` under worktree root and `pkg/`.

**Reproduce:** **reproduced** on this fork (copy of worktree sources + throwaway `explore_repro_test.go` in temp dir, not committed).

- Command: `go test -run TestExploreAppSecCancelBody -count=1 -v` from `C:\Users\DAVIDG~1\AppData\Local\Temp\opd-explore-appsec-cancel-72058561`
- `appsecQuery` with `context.Canceled` mid-read → `appsecQuery:GetBody context canceled`
- `handleNextServeHTTP` same body → **HTTP 403**, `next` not called (AppSec mock server not hit)

Outside facts: `knowledge/research/std_go_net-http_body-read-errors/notes.md`.

## Decisions

- **Seam:** classify or fail-open at `appsecQuery` `GetBody` error (before AppSec HTTP `Do`), not in `handleNextServeHTTP` — keeps ban mapping unchanged for real AppSec failures.
- **Rejected:** new config knob first — requirement allows pass-through; existing unreadable-body pattern is pass-through unless `appsecUnreadableBodyBlock`.
- **Rejected:** extend `isBodyUnreadable` for buffered bodies — that predicate is “never start ReadAll”; cancel happens mid-read on readable CL requests.
- **Proving test (implement):** table-driven cases in `bouncer_test.go` next to #323/#351 helpers; assert `appsecQuery` error today, and after fix assert nil + optional `handleNextServeHTTP` 200 to origin.
- **Live contract:** `no live contract` (no `openspec/` on this worktree; no AppSec delta spec in catalog).

## Open questions

- Q: Does this fork currently 403 when `io.ReadAll` fails on a client-cancelled body during AppSec buffering?
  Rank: additive asked — temp repro only; Desired fork-scope line names automated proof
  Decision: resolved — yes; `handleNextServeHTTP` returned 403 for `context.Canceled` mid-read (temp path above).
  By: explore

- Q: Fix shape — silent pass-through vs new fail-open configuration flag?
  Rank: bounded asked — changes existing `appsecQuery` error contract; 1 caller (`handleNextServeHTTP`) enumerated in `bouncer.go`
  Decision: assumed — silent pass-through (return nil from `appsecQuery` on client-disconnect class) aligned with unreadable-body spirit; no new knob unless implement finds an existing FailureAction pattern worth mirroring.
  By: explore

- Q: Which read errors count as client-gone vs genuine fault?
  Rank: additive asked — Desired names `context.Canceled`, HTTP/2 CANCEL, `io.ErrUnexpectedEOF`
  Decision: assumed — `errors.Is` for `context.Canceled` and `context.DeadlineExceeded`, plus `io.ErrUnexpectedEOF`; leave unclassified errors on the ban path until Traefik-specific evidence.
  By: explore

- Q: Where should the durable proving test live?
  Rank: additive asked — `requirement.md` Affected lists `bouncer_test.go`
  Decision: assumed — `bouncer_test.go` beside `Test_appsecQuery_streamingDoesNotBlock` / unreadable-body tests; reuse httptest AppSec server pattern.
  By: explore

- Q: Should `handleBanServeHTTP` be skipped when the client already disconnected?
  Rank: additive incidental — no acceptance criterion; optimize dead work only
  Decision: assumed — out of scope for #395; fixing `appsecQuery` to not error is enough; ban write on dead conn is harmless.
  By: explore

- Q: Effect on `blockedRequests` / LAPI dropped-request metrics if cancel pass-through?
  Rank: additive incidental — metric change not in scope (`requirement.md` Out of scope)
  Decision: assumed — fewer false APPSEC bans; no dedicated metric work in this ticket.
  By: explore
