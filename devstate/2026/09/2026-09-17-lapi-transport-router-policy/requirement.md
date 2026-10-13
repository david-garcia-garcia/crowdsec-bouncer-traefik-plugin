# Requirement
IssueKey: 2026-09-17-lapi-transport-router-policy

## Problem
A Traefik router reload that only changes per-router policy or LAPI HTTP/TLS settings creates a new `lapi.Client` and pays a CrowdSec `startup=true` resync. Those knobs are hashed into the stream reclaim key even though they do not own the LAPI cursor.

## Current (code)
- `pkg/lapi/client.go` — one `Client` holds cursor flags (`isCrowdsecStreamStartup`, `isCrowdsecStreamHealthy`, `updateFailure`), substitutable `httpClient`/`cacheClient`, and per-router policy (`lapiFailureAction`, `defaultDecisionTimeout`, `redisUnreachableBlock`) (`57-73`).
- `pkg/lapi/session.go` — reclaim key is `SessionPrefix` + FNV hash of 18-field `streamSettings` (`71-90`, `148-151`). `settingsFrom` copies failure action, `StreamStartupBlock`, `DefaultDecisionSeconds`, HTTP timeout, Redis fail-closed, and three TLS fields into that hash (`107-126`).
- `pkg/lapi/identity.go` — live/none `identity` / `IdentityHex` replicate the same policy, timeout, TLS, and `StreamStartupBlock` fields (`31-43`, `60-72`).
- `pkg/lapi/client.go` — `New` builds `*http.Client` from TLS + `HTTPTimeoutSeconds` and stores it as a plain field (`159-167`). `closeIdle` exists (`220`). `rangeMembership` already uses `atomic.Value` (`66`).
- `pkg/lapi/client_http.go` — `getToken` writes `c.crowdsecKey` (`71`); `crowdsecQuery` uses that key and `c.httpClient` (`85-88`).
- `pkg/bouncer/bouncer.go` — `Bouncer` has no LAPI failure-action or Redis fail-closed fields (`23-44`). `ServeHTTP` calls `lapiClient.RedisUnreachableBlock()` (`181`) and `applyLapiFailureAction` calls `lapiClient.LapiFailureAction()` (`236`). `appsecFailureAction` is already per-router via `EffectiveFailureAction` (`60`).
- `pkg/lapi/client.go` — accessors `LapiFailureAction()` / `RedisUnreachableBlock()` (`351-358`).
- `pkg/lapi/client_live.go` / `pkg/lapi/client_decisions.go` — live cache TTL reads `c.defaultDecisionTimeout` (`26,31`, `148-162`).
- `pkg/lapi/client_stream.go` — `StreamStartupBlock` is read only at construct (`37`); `handleStreamTicker` reads `updateFailure`, `updateMaxFailure`, `isCrowdsecStreamHealthy` without the mutex (`48-63`). `startTicker` launches `go work()` on each tick (`pkg/lapi/client.go:291-305`).
- `pkg/lapi/client.go` — `logInfo` emits mode+host only (`20-26`, `273-278`).
- `pkg/lapi/session.go` — live sibling with a different settings hash is warn-and-wire; first incarnation keeps knobs (`227-237`, `195-201`).
- `openspec/specs/core_plugin_middleware_instance-reclaim/spec.md` — settings hash includes intervals, Redis, HTTP timeout, LAPI failure action, LAPI TLS extras; second live New is first-wins warn-and-wire (`15-16`, `23-27`).
- `knowledge/devdocs/core_plugin_middleware.md` — documents `crowdsecLapiFailureAction` on LAPI Client identity (`22`, `66`).
- `knowledge/research/ext_crowdsec_lapi_stream-cursor/notes.md` — LAPI cursor is the bouncer row selected by SHA-512 of the API key plus the IP LAPI sees; `startup=true` zeros that cursor.
- `pkg/cache/cache.go` — memory cache ignores prefix; each `cache.Client` owns a map (`183-184`). `Close` is safe to call more than once (`251-257`).
- `pkg/lapi/zzz_session_test.go` / `zzz_plugin_test.go` — `waitStreamSessionInGrace` (`187-200`) and `waitPluginStreamInGrace` (`457-470`).

## Desired
- Move `lapiFailureAction`, `redisUnreachableBlock`, and `defaultDecisionTimeout` onto `Bouncer` (from `config`, `lapiFailureAction` via `EffectiveFailureAction`). Delete the Client accessors. Pass live TTL into `LiveLookup`; delete `c.defaultDecisionTimeout`.
- Drop those three plus `StreamStartupBlock` from `streamSettings` / `settingsFrom`. If `identity.go` still hashes them, drop them there too.
- Extract LAPI HTTP + auth (including CAPI token) into a transport type stored on `Client` with `atomic.Value` (not `atomic.Pointer[T]`). `AdoptTransport(cfg)` after Open: Store new, `closeIdle` old. Drop the three TLS fields and `HTTPTimeoutSeconds` from the settings hash.
- `logInfo` gains session key + `reason`. New INFO lines for transport replace (named fields) and for a live joiner whose settings differ (ignored vs adopted). Do not raise `pkg/reclaim` `reclaim_put` / `reclaim_reclaim` / `reclaim_dispose` to INFO.
- Tests: same Client + no extra `startup=true` fetch after failure-action-only reload; same Client + new transport after TLS-only reload; two bouncers apply distinct failure actions; per-router live TTL; existing grace wait helpers still pass.
- Do not make remaining write-once Client scalar fields mutable.

## Affected
- `pkg/lapi` (`client.go`, `client_http.go`, `client_live.go`, `client_decisions.go`, `client_stream.go`, `session.go`, `identity.go`, tests)
- `pkg/bouncer/bouncer.go` and its request path
- OpenSpec `core_plugin_middleware_instance-reclaim` (or a new leaf — FindSpecHost in propose)
- `knowledge/devdocs/core_plugin_middleware.md` language (failure action owner)

## Out of scope
- Shared `DecisionStore` / reclaim of `cache.Client` / atomic Redis lease via EVAL (`pkg/cache/cache.go` memory prefix ignore; `client_stream.go` `updated` lease).
- Narrowing the reclaim key to cursor-only: delete `Peek` / `PeekLivePrefix` / `View`, union live-router `scopes=`, replace in-tree `pkg/reclaim` with utilities import + process-table shim.
- `pkg/appsec`, captcha, AppSec.
- Moving `MetricsReporter` to its own reclaim piece.

## Unknowns
- Propose/FindSpecHost: fold parts 1–2 into `core_plugin_middleware_instance-reclaim` vs a new per-router-policy leaf.
- Whether live/none `IdentityHex` must drop the same fields this PR (ticket: review `identity.go` if it replicates — it does).

## Tensions
- Live spec `core_plugin_middleware_instance-reclaim` enumerates those fields in the settings hash and fixes warn-and-wire as first-wins. Parts 1–2 contradict that on purpose (policy becomes per-router; last `New` wins TLS/transport).
- Usage doc still says LAPI failure action lives on Client identity.
- Yaegi v0.16 cannot take a generic instantiation from another package as a struct field (`knowledge/research/ext_traefik-middleware-utilities_packages/notes.md`). Transport field must be `atomic.Value`, not `atomic.Pointer[T]`.
- Client scalars are write-once and ticker work reads them without the mutex. This PR must not convert remaining scalars to mutable; fields that move leave the object; transport is `atomic.Value`.
- Accepted: two routers on one cursor with different `defaultDecisionSeconds` last-write the live cache TTL.
- Desired vs today: two routers may differ on failure action and Redis fail-closed (today the joiner is ignored).
