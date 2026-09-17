## Context

See proposal.md — Why. `identity.go` and `connection_decisions.go` already split two jobs out of `connection.go`. The remaining 842-line file still owns construct/close, stream ticker, live lookup, AppSec, LAPI/CAPI HTTP, and metrics. Callers use the type (`plugin.go` `Prepare`/`New`, `pkg/bouncer` lookup). Client IP stays `pkg/ip.GetRemoteIP`. Reclaim identity stays `identity.go`. No `sync.Once` or package globals.

## Goals / Non-Goals

**Goals:**
- One job per named file listed in the proposal.
- Same package, same exported API, tests still pass.

**Non-Goals:**
- `pkg/appsec` or any new package.
- Moving `GetTLSConfigCrowdsec`.
- Changing `identity.go`, `DecisionScopeHeaders`, cache constants, `pkg/ip`, `configuration.go` layout, or `Prepare`/`plugin.go` mutation.
- Behavior, signatures, JSON tags, log strings, HTTP routes.

## Decisions

1. **`connection.go` keeps lifetime.** Type, `Prepare`, `New`, `Close`, accessors, range hydrate/store, `Decision` DTO, `startTicker`/`stopTicker`. Alternative: move tickers into stream/metrics files — rejected; both jobs share the helpers and `New`/`Close` own lifecycle.

2. **`closeIdle` lives in `connection_http.go`.** `Close` still calls it. Alternative: keep next to `Close` — weaker HTTP ownership.

3. **DTOs follow the job.** `Stream` with stream, `Login` with HTTP, AppSec types with AppSec. `Decision` stays in `connection.go` because stream, live, and `connection_decisions.go` all use it.

4. **Constants follow the job.** AppSec headers in `connection_appsec.go`. LAPI/CAPI routes and headers in `connection_http.go`. `cacheTimeoutKey` in `connection_stream.go`. Same-package visibility; `connection_decisions.go` keeps compiling.

5. **Move, do not rewrite.** Cut functions into the new files. Do not restyle, rename, or change control flow.

## Risks / Trade-offs

- [Init-cycle across files] → none; same package, no new imports between files.
- [Yaegi loads by package] → constructors stay on module root; this package is not the Yaegi entry.
- [Test helpers in `test_appsec_connection.go`] → stay; they already sit beside AppSec tests.

## Migration Plan

Plugin version bump is not required. Rollback is the previous tag (one `connection.go` again). No YAML keys.

## Open Questions

Assumed proceed policies live on `devstate/explore.md`.
