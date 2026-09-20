# Requirement
IssueKey: 2026-09-20-lapi-session-exclusive

## Problem
Two Traefik middleware names that share LAPI scheme+host+path+key currently Open the same DecisionStore and Client. That is the wrong control plane (closed PR 119 share-and-WARN). The store is the expensive session lock and warm cache; the Client is disposable. Sleep stops tickers but does not cancel in-flight LAPI GET, so Wake can run a second `startup=false` poll and steal CrowdSec cursor deltas.

## Current (code)
- `plugin.go` `New` opens LAPI then AppSec on `bindCtx` and cancels that ctx when `New` returns an error.
- `pkg/lapi/session.go` `OpenStream` / `OpenLive` Open the store first, then Open the Client with no name check; a second name joins (`lapi session joiner adopted`).
- `pkg/lapi/decisionstore.go` `StoreKey` is `decisionstore:` + `SessionHex` + Redis `storeParams` hash. `TestStoreKey_DifferentRedisHostsIsolate` requires different Redis hosts to be different keys.
- `pkg/decisionstore/store.go` `Store` has no `createdBy` or `streamReady`. `Open` create() binds memory vs Redis first-wins. Store reclaim Close is the store Close hook; `pkg/lapi/client.go` `Close` does not Close the store.
- `pkg/lapi/identity.go` live/none `Key` still hashes Redis + metrics interval. `SessionKey` still hashes Redis. Timeout and TLS are already out of those keys (`core_plugin_lapi_reclaim-key`).
- `pkg/lapi/client.go` `New` always sets `isCrowdsecStreamStartup` to 1. `Wake` resumes with that flag already 0 on the same Client (`zzz_session_test.go`). A new Client on a warm store still starts at 1.
- `pkg/lapi/client.go` `Sleep` stops tickers and `go drainMetrics()`. `Wake` immediately `go handleStreamTicker()`.
- `pkg/lapi/client_http.go` `sendQuery` uses `http.NewRequest` with no context. `closeIdle` exists. Metrics `query` is `crowdsecQuery` (`pkg/lapi/client_metrics.go`).
- `vendor/.../reclaim/table.go` has Open/OpenWithHooks, no Peek. `pkg/reclaim/default.go` re-exports OpenWithHooks only. `openspec/specs/std_go_reclaim_context-lease/spec.md` forbids exporting Peek. `openspec/specs/core_plugin_lapi_reclaim-key/spec.md` requires two names on the same cursor+Redis to share one Client.
- `.github/workflows/main.yml` runs `go mod vendor` with `git diff --exit-code ./vendor/` commented out.
- AppSec reclaim: `pkg/appsec/session.go` (unchanged ask).

## Desired
- Exact Peek on the DecisionStore reclaim key (no bind). Store write-once `createdBy` = Traefik name from the New that ran create(). Peek hit and createdBy != this name → error, do not Open, do not Wake. Peek miss or same name → Open store. Same name on many routers MUST share. Fail `New` for a second different name on the same LAPI session.
- Loud operator log/error: owner name, rejected name, clears when the old slot Closes, isolation is a second bouncer API key not a second middleware on the same key. Rename during 30s grace self-heals after Close. No table Release API. Failed New still cancels `plugin.go` bindCtx.
- Store reclaim key = `decisionstore:` + SessionHex only (no Redis hash). Client may still reclaim with Redis/intervals in the key. Timeout/TLS stay out; AdoptTransport last-wins. Reconfigure same name+mode: Open same store (bind/Wake); new or Woken Client; do not `startup=true`. `streamReady` on the store after the first finished stream poll; new Client reads it. Mode change → new SessionHex → empty store → startup=true. Client Close must not Close the store. Redis YAML change reuses existing store backend (first-wins). Live/none: same exclusive name rule; preserve store; no stream startup flag. AppSec reclaim unchanged.
- Client IO context: sendQuery/live lookups `NewRequestWithContext`. Sleep and Close cancel it. Wake mints a new WithCancel. drainMetrics must not use that ctx (Background). closeIdle stays.
- Exact Peek(key) → (value, awake|asleep, ok) on vendored utilities `reclaim/table.go`, re-export from `pkg/reclaim`. No PeekLivePrefix. No fork of the whole table into pkg/reclaim. knowledge/debt row: CI vendor restore / upstream Peek is follow-up; still ship the ad-hoc Peek.

## Affected
- `plugin.go`, `pkg/lapi/session.go`, `pkg/lapi/decisionstore.go`, `pkg/lapi/client.go`, `pkg/lapi/client_http.go`, `pkg/lapi/client_stream.go`, `pkg/lapi/client_decisions.go`, `pkg/decisionstore/store.go`, `pkg/reclaim/default.go`, vendored `traefik-middleware-utilities/reclaim/table.go`, tests under `pkg/lapi` / `pkg/reclaim` / `pkg/decisionstore`.
- Specs to change: `core_plugin_lapi_reclaim-key`, `std_go_reclaim_context-lease`, plus connection / query / decisionstore leaves as propose maps.

## Out of scope
Share-and-WARN subscribe; sessionResidue field lists; liveMiddlewareNames registry; PeekLivePrefix warn-and-wire; store-as-child Close; failing New on timeout-only reload; two Traefik processes; memory↔Redis migrate; parallel-create race closer; restoring PeekLivePrefix; implementing closed PR 119.

## Unknowns
- Exact Go types for Peek’s awake|asleep result (ticket names the triple, not the identifiers).
- Whether a vendor Peek survives a later `go mod vendor` that restores published v1.0.3 (CI vendor git-diff is commented out; ticket says ship Peek and debt the restore/upstream).

## Tensions
- Live spec `core_plugin_lapi_reclaim-key` says two names share one stream Client; this ticket fails the second name.
- Live spec `std_go_reclaim_context-lease` forbids Peek; this ticket requires exact Peek on vendor + shim export.
- DestBranch is `master` (has `pkg/lapi` reclaim). `origin/HEAD` is stale `main` and does not have that tree.
- Published utilities reclaim v1.0.3 has no Peek (`knowledge/research/ext_traefik-middleware-utilities_packages/notes.md`).
