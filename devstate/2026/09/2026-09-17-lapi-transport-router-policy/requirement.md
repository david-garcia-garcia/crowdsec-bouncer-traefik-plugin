# Requirement
IssueKey: 2026-09-17-lapi-transport-router-policy

## Problem
Traefik middleware reloads that change per-router policy or HTTP/TLS settings force a new reclaimed `lapi.Client` because those knobs sit in `streamSettings` and therefore in the session settings hash. That resets stream cursor state (`isCrowdsecStreamStartup`, etc.) and triggers a full CrowdSec stream resync even when the LAPI connection identity is unchanged.

## Current (code)
- `pkg/lapi/client.go:57-58,61,71-73` — per-router policy fields and cursor health live on the same `Client` as stream state.
- `pkg/lapi/client.go:64-65,159-167` — `httpClient` is built once in `New` and tied to the same reclaimed object as the cursor.
- `pkg/lapi/client.go:351-358` — `LapiFailureAction()` / `RedisUnreachableBlock()`; only callers `pkg/bouncer/bouncer.go:181,236`.
- `pkg/lapi/client_live.go:26,31` — live cache TTL uses `c.defaultDecisionTimeout`.
- `pkg/lapi/client_decisions.go:148-162` — `liveCacheTTL` uses `c.defaultDecisionTimeout`.
- `pkg/lapi/session.go:71-90,107-126` — `streamSettings` hash includes failure action, startup block, default decision seconds, HTTP timeout, TLS fields, Redis unreachable block, etc.
- `pkg/lapi/identity.go:31-32,61` — identity JSON mirrors `LapiFailureAction` and `StreamStartupBlock`.
- `pkg/lapi/client_stream.go:37` — `StreamStartupBlock` read only at stream start, not stored on `Client`.
- `pkg/lapi/client_http.go:71,85` — CAPI login mutates `c.crowdsecKey`; requests use `c.httpClient`.
- `pkg/lapi/client.go:274-278` — `logInfo` logs only `mode` and `host`.
- `pkg/bouncer/bouncer.go:29-44,57-69` — `Bouncer` has no failure-action / Redis-block / live TTL fields; delegates to `lapiClient` accessors.
- `pkg/lapi/zzz_session_test.go:187-200`, `zzz_plugin_test.go:457-470` — grace helpers for stream session tests (must keep working).

## Desired
- Move `lapiFailureAction`, `redisUnreachableBlock`, and live TTL (`defaultDecisionSeconds`) onto `Bouncer` from config (failure action via `configuration.EffectiveFailureAction` like `appsecFailureAction` at `bouncer.go:60`).
- Pass live TTL into `LiveLookup`; remove `defaultDecisionTimeout` and the two accessors from `Client`.
- Remove those three plus `StreamStartupBlock` from `streamSettings` / `settingsFrom` and from `identity.go` if duplicated.
- Extract hot-swappable LAPI HTTP transport (client + auth token handling) stored in `Client` via `atomic.Value` (not `atomic.Pointer[T]`); add `AdoptTransport(cfg)` after open with idle close of the previous client.
- Remove TLS trio + `HTTPTimeoutSeconds` from the settings hash.
- Extend INFO logging: session key + `reason` on lifecycle lines; INFO when transport is replaced (fields changed); INFO when a live joiner’s settings differ (ignored vs adopted fields). Do not promote `pkg/reclaim` debug reclaim lines to INFO.
- Tests: reload changing only failure action or TLS keeps the same reclaimed `*lapi.Client` without extra `startup=true` fetches; per-router failure action and live TTL behavior; existing grace test helpers still valid.

## Affected
- `pkg/lapi/` (`client.go`, `client_http.go`, `client_live.go`, `client_decisions.go`, `client_stream.go`, `session.go`, `identity.go`, tests)
- `pkg/bouncer/bouncer.go` (+ tests using `NewTestLapiFailureActionClient`)
- Plugin/reclaim wiring that calls `Open` / settings adoption (paths to confirm in explore)

## Out of scope
- Shared `DecisionStore` reclaim entry (local cache prefix ignored; stream lease not shared in memory — `pkg/cache/cache.go:183-184`, `client_stream.go:66-81`).
- Narrow session key to cursor only; remove reclaim `Peek` / `PeekLivePrefix` / `View`; union live router scopes; upstream reclaim import (`pkg/reclaim/peek.go`).
- Changes to `pkg/appsec`, captcha, or AppSec surfaces.
- Splitting `MetricsReporter` into its own reclaimed piece.

## Unknowns
- Exact reclaim `Open` / joiner hook where `AdoptTransport` runs after a reclaimed client is wired (call site not named in ticket).
- Whether `core_plugin_middleware_instance-reclaim` spec lives under `openspec/` on this branch (FindSpecHost in propose).

## Tensions
- Live spec `core_plugin_middleware_instance-reclaim` documents settings hash and warn-and-wire first-wins; parts 1–2 intentionally diverge (per-router policy off hash; last transport wins).
- Cursor scalar fields must stay write-once (no mutex on ticker path); ticket forbids making them mutable in this PR.
- Accepted: shared cache TTL last-writer when two routers differ on `defaultDecisionSeconds`; desired: distinct failure action and Redis fail-closed per router.
