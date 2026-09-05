# Explore
IssueKey: 2026-09-05-core-plugin-lifetime-refactor

## Concepts

**Plugin (Yaegi package)**:
The Go package Traefik evals for `CreateConfig` and `New`. Today that is root `crowdsec_bouncer_traefik_plugin` (`bouncer.go`). Traefik looks those two names up on `basePkg` after `import` of `.traefik.yml` `import`. It does not require a type named `Config` for middleware. Subpackages are GOPATH-loadable; they cannot replace the root constructor.
Owner: `knowledge/research/ext_traefik_plugins_yaegi-constructor/notes.md`.

**CrowdsecConnection**:
The process instance that talks to Crowdsec (LAPI/CAPI), owns the decision cache client, stream ticker, stream health, metrics ticker, and the HTTP clients used for those jobs. Not an HTTP handler. Not created per router.

**Bouncer**:
The per-router `http.Handler` Traefik gets back from `New`. It decides what happens on one incoming request (trusted IP, remediation, captcha page, ban template, whether to call AppSec on pass). It does not start tickers.

**Client address**:
Already owned by `pkg/ip.GetRemoteIP` (forwarded header + trusted proxy checker). The Bouncer calls that owner and passes the IP string into the Connection. The Connection does not parse `RemoteAddr`.

## Decisions

Recommended layout (no code in this phase):

```
github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin
│
├─ plugin.go                 package crowdsec_bouncer_traefik_plugin
│                            CreateConfig, New only
│                            New → CrowdsecConnection.Shared(config)
│                                → bouncer.New(next, name, routeCfg, conn)
│
├─ version.go                stay at root (metrics pluginVersion) or move with Connection
│
├─ pkg/crowdsecconnection/   type CrowdsecConnection
│                            cache client, LAPI/CAPI HTTP, stream ticker,
│                            stream health, metrics, AppSec HTTP client
│
├─ pkg/bouncer/              type Bouncer (http.Handler)
│                            next, trusted IPs, ban/captcha, route flags
│                            holds *CrowdsecConnection
│
└─ pkg/cache, captcha, configuration, ip, logger   unchanged jobs
```

Request path after the split:

```
Traefik router build
        │  New(ctx, next, config, name)   // once per router handler, not per request
        ▼
┌───────────────────┐     Shared/sync.Once (first New wins)
│ Plugin (root pkg) │──────────────────────────────┐
└─────────┬─────────┘                              ▼
          │                              ┌─────────────────────┐
          │                              │ CrowdsecConnection  │
          │                              │ cache, stream ticker│
          │                              │ LAPI/CAPI, metrics  │
          │                              └──────────▲──────────┘
          ▼                                         │ Lookup(ip) / LiveQuery / Healthy
┌───────────────────┐                               │
│ Bouncer (route)   │───────────────────────────────┘
│ ServeHTTP         │
│ GetRemoteIP       │
│ captcha / ban     │
└───────────────────┘
```

Current vs desired ownership:

| Job | Today | After |
| --- | --- | --- |
| Yaegi `CreateConfig`/`New` | `bouncer.go` mixed with everything | root `plugin.go` only |
| Stream ticker / health / `updateFailure` | package globals in `bouncer.go` 65–73, started at `New` 302–317 | fields on `CrowdsecConnection` |
| In-memory/redis cache client | each `Bouncer` has a `cache.Client` wrapping process `ttl_map` (`pkg/cache/cache.go` 31) | Connection holds the client; Bouncer does not construct cache |
| LAPI/CAPI HTTP | new `http.Client` per `New` (`bouncer.go` 244–252) | one client on Connection |
| AppSec HTTP | new client per `New`; host listed as first-wins in comment 47–62 | Connection owns client+host; Bouncer calls it when that route has AppSec enabled |
| Captcha challenge | `captcha.Client` on `Bouncer` | stays on Bouncer (request UX); grace/cache keys via Connection cache |
| Trusted IPs, ban template, remediation headers | `Bouncer` | `Bouncer` |
| `blockedRequests` / metrics push | globals + `reportMetrics(bouncer)` | Connection (`RecordDropped` from Bouncer) |
| Client IP | `ip.GetRemoteIP` from Bouncer | unchanged owner |

First-wins stays an explicit Connection rule (not hidden globals): the first `New` that calls `Shared` supplies LAPI host, stream interval, redis, AppSec host, metrics interval. Later routers share that instance even if their YAML differs. Same operator-visible behavior as `bouncer.go` 47–62.

## Reproduced

Not a runtime bug ticket. The claimed tangle is in tree.

- Traefik calls `New` once per router handler build, not per request, not once per process. Sourced in `ext_traefik_plugins_yaegi-constructor/notes.md`.
- First `New` with stream/alone mode starts `streamTicker`; later `New` sees non-nil and skips (`bouncer.go` 302–317). Same for `metricsTicker` (319–326).
- `TestNew`, `TestBouncer_ServeHTTP`, `Test_handleNoStreamCache`, `Test_handleStreamCache`, `Test_crowdsecQuery` are empty TODO tables (`bouncer_test.go` 43–194). Ban-template tests construct `Bouncer` by hand and never go through `New`.
- `go test ./...` on this Windows worktree: `pkg/cache`, `pkg/configuration`, `pkg/logger` ok. Root package FAIL only in `TestBouncerFileLoggingLevels` / `TestBouncerFileLoggingCommonFormat` TempDir cleanup: log file still open (`pkg/logger` `OpenFile` never closed). Assertions printed success. Not the lifetime bug; logger FD leak is out of scope unless we park the logger on Connection later.

## Coverage bar (this change)

Compiled `go test` owns lifetime. Existing mock e2e + real Pester e2e remain Yaegi-load proof. Do not add a third harness.

Must-have tests (replace empty TODOs; do not leave scaffolding):

1. `CrowdsecConnection.Shared` is once: two `New`/`Shared` calls return the same pointer; the second does not start a second ticker.
2. Parallel `Shared` (race): still one ticker.
3. Stream sync against `httptest` LAPI: `new`/`deleted` decisions land in the injected cache; `startup` query flag follows health/startup.
4. After `UpdateMaxFailure` stream errors, `Healthy` is false; a stream-mode Bouncer bans with `ReasonTECH`.
5. Live miss: Connection queries LAPI, writes cache, Bouncer remediates from the returned value.
6. Bouncer `ServeHTTP` with an injected Connection: disabled pass-through; trusted IP bypass; cache hit pass/ban/captcha; stream unhealthy; live miss. Uses `ip.GetRemoteIP` (do not re-parse `RemoteAddr`).
7. Plugin `New` twice: both handlers share one Connection.
8. Ban/HEAD template tests move with `pkg/bouncer` and keep today’s method/content-type matrix.

Inject `http.RoundTripper` (or `httptest.Server`), cache client, and a fake ticker/clock into Connection in tests. Production `Shared` wires the real ones. Do not add a second production `New` that only tests may call (`newTestConnection` is the test name).

## Out of this design

- Changing `.traefik.yml` `import` to a subpackage (`pkg/plugin`). Yaegi could load a prefixed import; catalog and local bind-mounts today target the module root. Thin the root package instead.
- Keying Connection by LAPI host/key (true multi-Crowdsec per Traefik process). That would change first-wins. Out of scope.
- Splitting `pkg/cache`’s process `ttl_map` into per-Connection maps in production memory mode (behavior change for tests/redis-less). Connection holds `*cache.Client`; tests inject a client.
- Public JSON config field names.

## Open questions

- Q: Must `CreateConfig`/`New` stay in the module-root package?
  Decision: assumed — yes. Keep `.traefik.yml` `import` as the module path. Thin root to `plugin.go`. Do not set `basePkg`. Sourced: Yaegi evals `basePkg.New` on the imported package (`ext_traefik_plugins_yaegi-constructor`).
  By: explore

- Q: One CrowdsecConnection per process, or one per LAPI identity?
  Decision: assumed — one per process via `Shared`/`sync.Once`, first `New` wins. Matches today’s globals. Keyed connections would be a product change.
  By: explore

- Q: Does captcha live on Connection or Bouncer?
  Decision: assumed — Bouncer (challenge HTML/provider is request UX). Cache keys for captcha grace go through the Connection’s cache client.
  By: explore

- Q: Does AppSec live on Connection or Bouncer?
  Decision: assumed — Connection owns the AppSec HTTP client and host (already first-wins in `bouncer.go` 47–62). Bouncer calls Connection on the pass path when that route has `CrowdsecAppsecEnabled`.
  By: explore

- Q: Type spelling `CrowdSecConnection` vs `CrowdsecConnection`?
  Decision: assumed — `CrowdsecConnection` and package `crowdsecconnection`, matching `CrowdsecLapiHost` / `CrowdsecMode`.
  By: explore

- Q: Who owns client address?
  Decision: resolved — `pkg/ip.GetRemoteIP` already owns it. Bouncer calls that; Connection receives the IP string only. Do not reconstruct from `RemoteAddr`.
  By: explore

- Q: How far does “exquisite” coverage go beyond compiled tests?
  Decision: assumed — lifetime is `go test` with fake LAPI and injected cache (list in Coverage bar). Mock e2e + real Pester stay the Yaegi proof. No new e2e suite in this change.
  By: explore
