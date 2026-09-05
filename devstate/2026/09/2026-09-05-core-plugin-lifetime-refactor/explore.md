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

**Key (assumed, differs from WAF on purpose):** `crowdsecconnection:` + FNV of the **connection** fields only (mode, LAPI/CAPI, redis, update/metrics intervals, AppSec host/client settings, HTTP timeout). Not Traefik middleware `name`. Not ban/captcha/trusted IPs/`Enabled`.

Sisters key `plugin:` + **name** + full config hash, so two WAF middleware names never share a core (`traefik-modsecurity/plugin_reuse_test.go` `TestNew_DifferentName_DoesNotShareCore`). Crowdsec today shares one stream across every middleware via globals. Putting `name` in the Connection key would start **one ticker per middleware name** (regression vs today). Connection identity is LAPI, not the Traefik alias.

Same LAPI, two names, N routers → one Connection, N Bouncers. Config reload (cancel all holders, `New` within 10s) → `reclaim_reclaim`, same ticker. Last route gone + 10s → `Close()`. Two different LAPI hosts → two Connections (this **does** change first-wins-everything when operators actually configured two Crowdsecs; that is the instance the ticket asked for).

## Reproduced

- Traefik `New` per router-handler build: `ext_traefik_plugins_yaegi-constructor`.
- This plugin discards `ctx` (`New(_ context.Context`) and never stops tickers. Sisters bind `ctx` with reclaim because Traefik cancels then reconstructs across a ~1 ms gap (`std_go_reclaim` gotcha).
- WAF `bindPlugin`: `reclaim.Open` then `ForRoute(next)` (`traefik-modsecurity/modsecurity.go` 40–53). Geoblock the same (`plugin.go` 42–54).
- Empty `TestNew` / stream / query tables (`bouncer_test.go` 43–194).
- `go test ./...` Windows: pkg tests ok; root logging tests fail TempDir cleanup (open log FD). Not the lifetime bug.

## Coverage bar (this change)

Compiled `go test` owns lifetime. Copy the WAF reuse test shape (`plugin_reuse_test.go`): `reclaim.ResetWith` in cleanup; cancelable holder ctx (not Background for grace tests). Existing mock e2e + real Pester stay Yaegi-load proof.

Must-have:

1. Two `New` with live ctx and the same connection fields → same `*CrowdsecConnection`, one ticker (including different middleware names).
2. Parallel `Open` race: one incarnation.
3. Cancel all holders, `Open` same key before grace → reclaim, no second `create`, ticker still running (`reclaim_reclaim`).
4. Cancel, wait past grace → `Close()` ran; next `Open` creates a new Connection (`reclaim_dispose`).
5. Different LAPI host (different key) → two Connections, two tickers, **isolated caches** (A’s `Set` is not B’s `Get`, including Redis prefix).
6. Stream sync against `httptest` LAPI; unhealthy after `UpdateMaxFailure`; live miss query.
7. Bouncer `ServeHTTP` with injected Connection: disabled, trusted IP, cache hit pass/ban/captcha, stream unhealthy, live miss. `ip.GetRemoteIP` only.
8. Ban/HEAD template matrix moves with `pkg/bouncer`.
9. Production `create` takes **no** args (Yaegi). Tests use `newTestConnection` / `reclaim.NewTable` with short grace.

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
  Decision: assumed — `crowdsecconnection:` + hash of LAPI/CAPI/redis/stream/AppSec client fields only. Name and ban/captcha/trusted IPs stay off the key so two aliases with the same LAPI share one ticker (today’s globals) without first-wins hiding a second LAPI.
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
  Decision: assumed — `go test` with reclaim grace/reclaim/dispose plus fake LAPI. Existing e2e is Yaegi proof.
  By: explore

- Q: Is the memory cache a process singleton?
  Decision: resolved — each Connection has isolated cache space. Drop `pkg/cache` `var cache`. Memory: one `ttl_map` per Client. Redis: prefix every key with the connection identity so two Connections on one Redis do not share decisions, captcha grace, or the `"updated"` lease. Same reclaim key → same Connection → same cache (that is share-by-identity, not a process dump).
  By: explore
