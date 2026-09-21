# Explore

Verdict: **ready** (propose complete; decisions carried into change `2026-09-21-appsec-cancelled-body-ban`).

Upstream: [maxlerebourg/crowdsec-bouncer-traefik-plugin#395](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/395). Fork PR [#133](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/133) (base **master**).

## Concepts

```
Client POST (HTTP/2, Content-Length set, readable body)
        │
        ▼
Bouncer.handleNextServeHTTP
        │
        ├─ appsecEnabled ──► appsecClient.Query
        │                         │
        │                    newAppsecForwardRequest
        │                         │
        │                    newAppsecBodyRequest
        │                         │
        │                    isBodyUnreadable? ──no (CL≥0, not streaming)
        │                         │
        │                    io.ReadAll(TeeReader(LimitReader(Body)))
        │                         │
        │                    err != nil ──► fmt.Errorf("appsecQuery:GetBody %w", err)
        │                         │              (no resultForFailureAction)
        │                         ▼
        └─ applyAppsecServeHTTP: err ──► handleBanServeHTTP(ReasonAPPSEC) ──► 403
```

| Unit | Path | Job |
|------|------|-----|
| Body buffer | `pkg/appsec/query.go` `newAppsecBodyRequest` | Copy readable POST/PUT/PATCH/DELETE body; `GetBody` errors bypass `FailureAction` |
| AppSec round-trip | `pkg/appsec/query.go` `Query` | Unreachable / 500 / response-body io / unreadable H2 body use `resultForFailureAction` |
| Unreadable predicate | `pkg/appsec/query.go` `isBodyUnreadable` | HTTP/2+ **without** Content-Length only; mid-read cancel is not unreadable |
| Ban wiring | `pkg/bouncer/bouncer.go` `applyAppsecServeHTTP` | Any `Query` error except `ErrFailureCaptcha` → ban |
| Config | `pkg/configuration/configuration.go` | `bouncerAppsecFailureAction` per router; default `ban` |
| Tests today | `pkg/appsec/zzz_query_test.go` | Streaming/unreadable/failure-action; **no** mid-read cancel on buffered body |

**Call sites** where a `Query` error becomes a ban: **1** — `applyAppsecServeHTTP` in `pkg/bouncer/bouncer.go` (searched `*.go` under worktree `pkg/`).

**Reproduce:** **reproduced** on this worktree (`master` product layout).

- Temp dir (not committed): `C:\Users\DAVIDG~1\AppData\Local\Temp\opd-explore-appsec-cancel-301881134`
- Command (overlay tests; no product-tree test files):
  - `go test -overlay=<tmpdir>\overlay.json ./pkg/appsec/ -run TestExploreAppSecCancelBody_Query -count=1 -v`
  - `go test -overlay=<tmpdir>\overlay_bouncer.json ./pkg/bouncer/ -run TestExploreAppSecCancelBody_HandleNext403 -count=1 -v`
- **Query + `FailureAction: passthrough`:** error `appsecQuery:GetBody context canceled`; AppSec httptest server **not** hit.
- **`handleNextServeHTTP` same body:** **HTTP 403**; `next` **not** called; DEBUG log `appsecQuery:GetBody context canceled`.

Outside facts: `knowledge/research/std_go_net-http_body-read-errors/notes.md`.

## Decisions

- **Seam:** classify or fail-open in `pkg/appsec/query.go` `newAppsecBodyRequest` when `io.ReadAll` fails (before AppSec `Do`). Keep `applyAppsecServeHTTP` ban mapping for genuine AppSec failures.
- **Rejected:** extend `isBodyUnreadable` for mid-stream errors — that gate means “never start buffering”; cancel happens on readable CL requests.
- **Rejected:** new public config knob first — requirement and #395 prefer pass-through spirit; fork already centralizes fallbacks on `bouncerAppsecFailureAction`.
- **Fix-shape lean:** stop without ban, origin, or FailureAction; TRACE log; optional `error:client-disconnected` header for Traefik access logs. Requester confirmed.
- **Proving test (implement):** table in `pkg/appsec/zzz_query_test.go` (requirement Affected); assert today’s `GetBody` error + optional bouncer overlay pattern; after fix assert passthrough allows without AppSec call / without 403.
- **Live contract:** `openspec/specs/core_plugin_appsec_failure-action` + `core_plugin_appsec_client`. Failure-action covers 500, unreachable, unreadable H2/H3 body (no CL), and **AppSec response-body** io — **does not** mention client request-body `GetBody` / mid-buffer read failure. Propose may **ADD** a scenario on that family; client spec covers copy/limit methods only.

## Open questions

- Q: Does this fork 403 when `io.ReadAll` fails on a client-cancelled body during AppSec buffering?
  Rank: additive asked — Desired fork-scope line names automated proof
  Decision: resolved — yes; repro above (`Query` error + `handleNextServeHTTP` 403 even with `passthrough`).
  By: explore

- Q: Fix shape — silent pass-through vs `resultForFailureAction` vs new knob?
  Rank: bounded asked — changes `newAppsecBodyRequest` error contract; **1** caller (`applyAppsecServeHTTP`) enumerated in `pkg/bouncer/bouncer.go`
  Decision: resolved — stop without ban, origin, or FailureAction; TRACE log; optional `bouncerRemediationHeader=error:client-disconnected`. Requester confirmed 2026-09-21 (chat).
  By: implement

- Q: Which read errors count as client-gone vs genuine fault?
  Rank: additive asked — Desired names cancel, H2 CANCEL, unexpected EOF
  Decision: assumed — `errors.Is` for `context.Canceled`, `context.DeadlineExceeded`, and `io.ErrUnexpectedEOF`; unclassified `GetBody` errors stay on the ban path until Traefik-specific evidence.
  By: explore

- Q: Where should the durable proving test live?
  Rank: additive asked — `requirement.md` Affected lists `pkg/appsec/zzz_query_test.go`
  Decision: assumed — `zzz_query_test.go` beside streaming/unreadable/failure-action tests; bouncer 403 wiring can stay a focused test in `pkg/bouncer/zzz_bouncer_test.go` only if implement needs end-to-end proof beyond `Query`.
  By: explore

- Q: Should `handleBanServeHTTP` be skipped when the client already disconnected?
  Rank: additive incidental — no acceptance criterion; optimize dead work only
  Decision: assumed — out of scope for #395; fixing `Query`/`GetBody` classification is enough.
  By: explore

- Q: Effect on LAPI dropped-request / blocked metrics if cancel pass-through?
  Rank: additive incidental — `requirement.md` Out of scope for metrics work
  Decision: assumed — fewer false APPSEC bans; no dedicated metric change in this ticket.
  By: explore
