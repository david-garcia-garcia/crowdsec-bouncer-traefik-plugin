# Explore
IssueKey: 2026-09-05-core-plugin-lifetime-refactor

## Concepts

**Plugin (Yaegi package)**:
The Go package Traefik evals for `CreateConfig` and `New`. Today that is root `crowdsec_bouncer_traefik_plugin` (`bouncer.go`). Traefik looks those two names up on `basePkg` after `import` of `.traefik.yml` `import`. Subpackages cannot replace the root constructor.
Owner: `knowledge/research/ext_traefik_plugins_yaegi-constructor/notes.md`.

**Reclaim table**:
A process-wide keyed store of `any` plus holder contexts. First `Open` for a key runs `create`. Later `Open` with a live context binds another holder. When every holder’s context is Done, grace starts (`DefaultGrace` 10s). An `Open` in that window is a reclaim (same incarnation, no `create`). If grace elapses, the table cancels the incarnation lifetime and calls `Close()` if the value has it. `ctx` is Traefik’s `New` context (`WithCancel`); the next dynamic config cancels it ~1 ms before the next `New`. Not `req.Context()`, not `context.Background()` as the production holder (Background is accepted in tests).
Owner (sister): `D:\repositories\traefik-geoblock\pkg\reclaim\table.go`, `knowledge/devdocs/std_go_reclaim.md`; WAF `D:\repositories\traefik-modsecurity\modsecurity.go` `bindPlugin`, `knowledge/devdocs/core_plugin_reclaim.md`.
_Avoid_: `sync.Once` that never disposes; package globals; ignoring Traefik `New` ctx (`bouncer.go` today: `New(_ context.Context, …)`).

**CrowdsecConnection**:
The reclaim *value* for one Crowdsec LAPI/CAPI identity. Owns cache client, stream ticker, stream health, metrics ticker, LAPI/CAPI HTTP, AppSec HTTP client. Implements `Close()` to stop tickers and drop idle connections. Not an `http.Handler`. Not created per router. Mapped to geoblock/modsecurity **Plugin** (shared core).

**Bouncer**:
The per-router `http.Handler` Traefik gets back from `New`. Holds `next` plus per-route request policy (trusted IPs, ban/captcha, Enabled, whether to call AppSec on pass) and a pointer to the reclaimed Connection. Mapped to geoblock/modsecurity **Route** / `ForRoute(next)`. Cannot be the reclaim value (`next` is per router).

**Client address**:
Already owned by `pkg/ip.GetRemoteIP`. Bouncer calls that; Connection receives the IP string.

## Purpose

Kill first-wins globals so **one Traefik process can run two Crowdsec bouncer configs at once**: side-by-side config comparison, and multiple Crowdsec backends. Readability is a consequence. If two live configs still share a ticker or a cache, the split failed.

## Decisions

Copy `pkg/reclaim` from geoblock (stdlib table, non-generic `any`, Yaegi-safe `create func() (any, error)`). Do not rewrite it. Do not use `Table[*T]` from another package (Yaegi panics).

Root `New` must **use** Traefik `ctx` (stop discarding it):

```
New(ctx, next, config, name)
  Prepare/validate config
  logger := …
  stored, err := reclaim.Open(ctx, connectionKey(config), logger, func() (any, error) {
      return newCrowdsecConnection(config, logger)
  })
  conn := stored.(*CrowdsecConnection)
  return bouncer.New(next, name, routeCfg, conn)   // ForRoute
```

```
Traefik dynamic config
        │  cancels previous New ctx (~1 ms), then New again
        ▼
┌───────────────────┐
│ plugin.go         │  reclaim.Open(ctx, key, logger, create)
│ CreateConfig, New │
└─────────┬─────────┘
          │ bind / reclaim / create
          ▼
┌─────────────────────┐     last holder Done → orphan → grace 10s
│ CrowdsecConnection  │     Open in grace → reclaim (no create)
│ cache, stream ticker│     grace elapsed → Close() (stop tickers)
│ LAPI/CAPI, metrics  │
└──────────▲──────────┘
           │ Lookup / LiveQuery / Healthy
┌───────────────────┐
│ Bouncer (route)   │  new each New; holds this next
│ ServeHTTP         │
└───────────────────┘
```

Current vs desired ownership:

| Job | Today | After |
| --- | --- | --- |
| Yaegi `CreateConfig`/`New` | `bouncer.go`; **`ctx` ignored** | root `plugin.go`; `ctx` is reclaim holder |
| Stream ticker / health | package globals; never stopped | Connection fields; `Close()` stops them |
| Cache client | each Bouncer wraps process `ttl_map` | Each Connection has an **isolated** store. Memory: private `ttl_map`, not the package var. Redis: same host still isolated via a key prefix = connection identity. Bouncer and captcha use that Connection’s Client only |
| LAPI/CAPI HTTP | new `http.Client` per `New` | one client on that Connection incarnation |
| AppSec HTTP | new client per `New`; host first-wins | Connection owns client+host; Bouncer calls on pass when enabled |
| Captcha | on `Bouncer` | stays on Bouncer; cache via Connection |
| Ban template, trusted IPs, `next` | `Bouncer` | `Bouncer` (not in Connection key) |
| Metrics / dropped count | globals | Connection; `Close` ends the push loop |
| Client IP | `ip.GetRemoteIP` | unchanged |

**Key (resolved for two configs):** `crowdsecconnection:` + FNV of **connection** fields (mode, LAPI/CAPI, redis, update/metrics intervals, AppSec host/client settings, HTTP timeout). Not Traefik middleware `name`. Not ban/captcha/trusted IPs/`Enabled`.

Same connection fields, two middleware names, N routers → one Connection (one backend, many routes). **Different** connection fields (other LAPI host/key, other mode, other redis, other stream interval, …) → **two Connections in the same process**, isolated caches and tickers. That is the product behavior. Today’s first-wins (`bouncer.go` 47–62) is what we remove.

WAF keys `plugin:` + name + full config so two *names* never share a core. We do not copy that for Connection: two aliases aimed at the same LAPI should still share one ticker. Two aliases aimed at different LAPIs (or different stream/live/redis) must not.

## Reproduced

- Traefik `New` per router-handler build: `ext_traefik_plugins_yaegi-constructor`.
- This plugin discards `ctx` (`New(_ context.Context`) and never stops tickers. Sisters bind `ctx` with reclaim because Traefik cancels then reconstructs across a ~1 ms gap (`std_go_reclaim` gotcha).
- WAF `bindPlugin`: `reclaim.Open` then `ForRoute(next)` (`traefik-modsecurity/modsecurity.go` 40–53). Geoblock the same (`plugin.go` 42–54).
- Empty `TestNew` / stream / query tables (`bouncer_test.go` 43–194).
- `go test ./...` Windows: pkg tests ok; root logging tests fail TempDir cleanup (open log FD). Not the lifetime bug.

## Coverage bar (this change)

The claim to prove: **two bouncer configs in one process do not share ticker, cache, or LAPI**. First-wins is a failing test, not a comment.

Compiled `go test` owns that claim (two `httptest` LAPIs, two `New` in one test). Copy WAF reuse tests for reclaim (`plugin_reuse_test.go`): `reclaim.ResetWith` in cleanup; cancelable holder ctx. Mock e2e proves the same claim **through Traefik** (one binary, two named middlewares). Existing scenarios stay. Real Pester is extra, not a substitute for the two-config tests.

Must-have:

1. Two `New` with live ctx and the **same** connection fields → same `*CrowdsecConnection`, one ticker (including different middleware names).
2. Parallel `Open` race: one incarnation per key.
3. Cancel all holders, `Open` same key before grace → reclaim, no second `create`.
4. Cancel, wait past grace → `Close()`; next `Open` is a new Connection.
5. **Two configs in one process (the point):** `New` with LAPI-A and `New` with LAPI-B (two `httptest` servers). Two Connection pointers. Ban IP X only on A → Bouncer-A remediates X, Bouncer-B does not. Isolated caches (A `Set` ≠ B `Get`). Two stream tickers; A’s stream `new` does not appear in B. Same IP can be banned on A and allowed on B at the same time.
6. Side-by-side **mode** configs: stream Connection vs live Connection in one process; live miss queries only B’s LAPI; stream poll only A’s stream endpoint.
7. Redis prefix: two Connections, same Redis host, isolated keys (decisions, `"updated"` lease, captcha grace).
8. Bouncer `ServeHTTP` matrix with injected Connection: disabled, trusted IP, cache hit pass/ban/captcha, stream unhealthy, live miss. `ip.GetRemoteIP` only.
9. Ban/HEAD template matrix moves with `pkg/bouncer`.
10. Production `create` takes **no** args (Yaegi).
11. **Mock e2e:** one Traefik, two routers, two middleware names, two LAPI mocks (or two keys). Request on router A follows config A; router B follows config B. Fail if first-wins (B sees A’s stream/cache). New scenario under `tests/e2e/mock/scenarios/`, not a third harness.

## Out of this design

- Changing `.traefik.yml` `import` to a subpackage.
- Rewriting `pkg/reclaim` (copy from geoblock).
- Keying Connection by Traefik middleware **name** (WAF’s `plugin:name:hash`). That would split tickers per alias.
- Public JSON config field names.

Memory-mode store is **not** the package `ttl_map`. Each Connection owns an isolated cache space (private map, or Redis keys prefixed with that connection’s identity). Tests inject a Client. Captcha uses that same Client (`ip+"_captcha"`). The `"updated"` stream lease is per Connection, not process-wide.

## Open questions

- Q: Must `CreateConfig`/`New` stay in the module-root package?
  Decision: assumed — yes. Thin root to `plugin.go`. Do not change `.traefik.yml` `import`.
  By: explore

- Q: How is CrowdsecConnection shared — `sync.Once`, or reclaim?
  Decision: resolved — reclaim table, copied from geoblock/modsecurity. Traefik `New` ctx is the holder. `Close()` on unreclaimed incarnation. Not `sync.Once`.
  By: explore

- Q: Reclaim key = middleware name + full config (WAF), or connection-field hash without name?
  Decision: resolved — `crowdsecconnection:` + hash of connection fields (not name). Same backend shares; different backends/configs are two Connections in one Traefik. That is the ticket.
  By: explore

- Q: Does captcha live on Connection or Bouncer?
  Decision: assumed — Bouncer. Cache keys through Connection.
  By: explore

- Q: Does AppSec live on Connection or Bouncer?
  Decision: assumed — Connection owns HTTP client+host (in the reclaim key). Bouncer calls it on pass when that route has AppSec enabled.
  By: explore

- Q: Type spelling `CrowdSecConnection` vs `CrowdsecConnection`?
  Decision: assumed — `CrowdsecConnection` / `pkg/crowdsecconnection`.
  By: explore

- Q: Who owns client address?
  Decision: resolved — `pkg/ip.GetRemoteIP`. Connection receives the IP string only.
  By: explore

- Q: How far does “exquisite” coverage go beyond compiled tests?
  Decision: resolved — `go test` must fail if two configs in one process share ticker/cache/LAPI (two httptest LAPIs). Mock e2e adds one scenario: one Traefik, two middlewares, two LAPIs. Real Pester is not a substitute.
  By: explore

- Q: Is the memory cache a process singleton?
  Decision: resolved — each Connection has isolated cache space. Drop `pkg/cache` `var cache`. Memory: one `ttl_map` per Client. Redis: prefix every key with the connection identity so two Connections on one Redis do not share decisions, captcha grace, or the `"updated"` lease. Same reclaim key → same Connection → same cache (that is share-by-identity, not a process dump).
  By: explore
