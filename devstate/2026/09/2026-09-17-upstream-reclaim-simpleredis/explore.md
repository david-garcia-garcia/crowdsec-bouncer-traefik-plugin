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
  Decision: resolved — `go.mod` requires `github.com/david-garcia-garcia/traefik-middleware-utilities v1.0.3`. Vendored `simpleredis`; source-synced `reclaim/` into `pkg/reclaim` (Peek stays in-package). `pkg/simpleredis` deleted.
  By: implement

- Q: Must reclaim call sites move from `*reclaim.Wrapped` / value methods to upstream `Hooks`?
  Decision: resolved — yes. LAPI/AppSec sessions pass `reclaim.Hooks` via `OpenWithHooks`. `*Wrapped` removed.
  By: implement

- Q: Upstream has no `OpenWithGrace` (grace is table-wide). How do LAPI/AppSec keep a 30s wait while `DefaultGrace` stays 10s?
  Decision: resolved — process table is `New(Config{Grace: ProcessGrace})` (30s). `lapi.ReclaimGraceDuration` / `appsec.ReclaimGraceDuration` stay 30s aliases for tests. Tests that need zero/short grace call `ResetForTestWith`. Utilities `DefaultGrace` (10s) is unchanged.
  By: implement

- Q: Upstream reclaim has no `Peek` / `PeekLivePrefix` / `View`. Can OpenStream warn-and-wire stay?
  Decision: resolved — Peek/PeekLivePrefix/View live on `pkg/reclaim` next to the synced table. No vendor patch.
  By: implement

- Q: Cache commands have no `context.Context` today; upstream requires one. What ctx?
  Decision: resolved — `context.Background()` on `pkg/cache` Redis paths. Request ctx is out of this swap.
  By: implement

- Q: Upstream SimpleRedis default timeouts (dial 200ms, command 900ms) differ from in-tree (dial 2s, I/O 1s). Pin what?
  Decision: resolved — `simpleredis.Config` keeps dial 2s and command 1s.
  By: implement

- Q: Live spec `core_cache_redis_in-tree-client` forbids tracking an outside simpleredis repo and requires the in-tree import path.
  Decision: resolved — this change updates the Redis-client rules onto `core_cache_redis_utilities-client` and deletes the old leaf (it names `pkg/simpleredis`). Still not `maxlerebourg/simpleredis`.
  By: propose

- Q: Which utilities version do we pin if tags move during the run?
  Decision: resolved — `v1.0.3`.
  By: implement
