# Explore
IssueKey: 2026-09-17-upstream-reclaim-simpleredis

## Concepts

```
  DestBranch master                         utilities v1.0.3
  ----------------------                    ----------------------
  pkg/reclaim                               reclaim/
    Default / Open / OpenWithGrace            New(Config{Grace})
    *Wrapped → Sleep/Wake/Close               Open(..., Hooks)
    Peek / PeekLivePrefix / View              (none — unexported map)
    ResetForTest / ResetForTestWith           Reset()
  pkg/simpleredis                           simpleredis/
    Init(host, pass, database)                New(Config) (*Client, error)
    Get/MGet/Set/Del (no ctx)                 Get/MGet/Set/Del(ctx, …)
    error strings only                        strings + Err* + Is*
  vendor/leprosus/golang-ttl-map            (Yaegi sees vendor/ only)
```

**Reclaim table** (usage `std_go_reclaim`): process table bound to Traefik `New` ctx. Last holder Sleeps; Open during grace Wakes. LAPI stream warn-and-wire reads `PeekLivePrefix` then `Peek` (`pkg/lapi/session.go`).

**In-tree SimpleRedis** (usage `core_cache_redis`): `Init` then pointer-held `Get`/`MGet`/`Set`/`Del`. Cache maps `redis:miss` / `redis:unreachable` by `err.Error()`.

**Yaegi load**: constructor stays at module root. Subpackages and `vendor/` are GOPATH imports. This tree already vendors `golang-ttl-map`. A new module that is not vendored will not load under local/catalog Yaegi.

**Identity**: this swap does not choose client address, user, tenant, Host, or trust hop. Owner stays `pkg/ip.GetRemoteIP`.

## Decisions

Replace the ad-hoc copies, do not keep a silent second fork of simpleredis, and do not drop stream Peek.

```
  go.mod require utilities v1.0.3
           │
           ├─ simpleredis ── vendor ── delete pkg/simpleredis
           │                 cache imports the module; New + ctx
           │
           └─ reclaim ── source-sync into pkg/reclaim
                         (same import path; Peek stays in-package)
                         call sites pass Hooks, not *Wrapped
```

## Open questions

- Q: How do we take “upstream versions” (go.mod require, vendor copy into `pkg/`, or submodule)?
  Decision: assumed — `go.mod` require `github.com/david-garcia-garcia/traefik-middleware-utilities v1.0.3` (`950b08d`). Vendor that module the same way `golang-ttl-map` is vendored. Delete `pkg/simpleredis` and import `…/simpleredis`. Source-sync upstream `reclaim/` files into `pkg/reclaim` (do not import the module for reclaim): Peek/PeekLivePrefix must read the table map, which is unexported, and CI `go mod vendor` would wipe a vendor patch (`skill:sbs-dev-workflow:Issues` upstream-blocker rule).
  By: explore

- Q: Must reclaim call sites move from `*reclaim.Wrapped` / value methods to upstream `Hooks`?
  Decision: assumed — yes. `lapi.wrappedClient` and the AppSec create func pass `reclaim.Hooks{Sleep, Wake, Close}` into `Open` / `OpenWithHooks`. Drop `*Wrapped`. Same Yaegi reason: funcs, not a type assert on a foreign concrete type.
  By: explore

- Q: Upstream has no `OpenWithGrace` (grace is table-wide). How do LAPI/AppSec keep a 30s wait while `DefaultGrace` stays 10s?
  Decision: assumed — process table is `New(Config{Grace: ReclaimGraceDuration})` (30s). Production only calls `OpenWithGrace(..., 30s, ...)`. Tests that need zero/short grace construct or `Reset` a table with that grace. Update `std_go_reclaim_context-lease` / usage so this plugin’s process table wait is 30s; do not change the utilities constant `DefaultGrace` (10s).
  By: explore

- Q: Upstream reclaim has no `Peek` / `PeekLivePrefix` / `View`. Can OpenStream warn-and-wire stay?
  Decision: assumed — yes, by keeping those helpers on the in-tree `pkg/reclaim` package next to the synced table (same package can see `items`). Do not drop prefix peek. Do not invent a sidecar map. Do not patch `vendor/`.
  By: explore

- Q: Cache commands have no `context.Context` today; upstream requires one. What ctx?
  Decision: assumed — `context.Background()` on `pkg/cache` Redis paths this change touches. Stream ticks and `Client.Get`/`Set` have no request ctx today. Threading `req.Context()` through cache is a later note, not this swap.
  By: explore

- Q: Upstream SimpleRedis default timeouts (dial 200ms, command 900ms) differ from in-tree (dial 2s, I/O 1s). Pin what?
  Decision: assumed — pass an explicit `simpleredis.Config` that keeps this plugin’s current dial 2s and command 1s (idle 30s, pool 8). Do not silently take upstream’s tighter defaults.
  By: explore

- Q: Live spec `core_cache_redis_in-tree-client` forbids tracking an outside simpleredis repo and requires the in-tree import path.
  Decision: assumed — this change updates that spec so the Redis client is the vendored utilities module (still not `maxlerebourg/simpleredis`). Spec id stays; a rename of the leaf is a follow-up note, not a silent rename.
  By: explore

- Q: Which utilities version do we pin if tags move during the run?
  Decision: assumed — `v1.0.3`. Do not follow `master`.
  By: explore
