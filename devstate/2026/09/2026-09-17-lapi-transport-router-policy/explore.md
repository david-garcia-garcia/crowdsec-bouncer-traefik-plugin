# Explore
IssueKey: 2026-09-17-lapi-transport-router-policy

## Concepts

Traefik calls `New` once per router-handler build and cancels that constructor `ctx` on reload shortly before the next `New` (`ext_traefik_plugins_yaegi-constructor`). This process already binds that `ctx` through in-tree `pkg/reclaim` (`std_go_reclaim`, `plugin.go` `OpenStream` / `OpenLive`). Sister geoblock/modsecurity reclaim is the same table contract: last holder `Sleep`s, Open during grace `Wake`s, grace `Close`s. There is no `core_plugin_reclaim` packet; usage lives on `core_plugin_middleware.md`. Do not add `sync.Once` or a new process singleton.

CrowdSec LAPI owns the stream cursor on the **bouncer row** selected by SHA-512 of `X-Api-Key` plus the IP LAPI sees (this process’s outbound address). `startup=true` zeros that cursor and returns the full active set (`ext_crowdsec_lapi_stream-cursor`). Two in-process pollers on the same row steal deltas. This plugin’s reclaim key is **not** that cursor: stream/alone `SessionKey` = `SessionPrefix` (URL+key) + FNV of 18-field `streamSettings`; live/none `Key` = `lapi:` + `IdentityHex` of the same knob cluster (`session.go` 71–90, `identity.go` 19–44).

Today those hashes include per-router policy (`lapiFailureAction`, `redisUnreachableBlock`, `defaultDecisionSeconds`, `StreamStartupBlock`) and LAPI HTTP/TLS (`HTTPTimeoutSeconds`, three TLS fields). A Traefik reload that only changes those knobs therefore `Open`s a new `lapi.Client` and pays `startup=true`. `Bouncer` already owns AppSec failure action; it still reads LAPI policy through `Client` accessors (`bouncer.go` 181, 236). Live cache TTL is `c.defaultDecisionTimeout` inside `LiveLookup` (`client_live.go`, `client_decisions.go`).

`httpClient` is a plain `*http.Client` built in `New` (TLS + timeout). CAPI `getToken` writes `c.crowdsecKey` (`client_http.go` 71). `rangeMembership` already uses `atomic.Value` (`client.go` 66). Yaegi v0.16 cannot take a generic instantiation from another package as a struct field (`ext_traefik-middleware-utilities_packages`); `atomic.Pointer[T]` is out.

Live spec `core_plugin_middleware_instance-reclaim` enumerates those fields in the settings hash and fixes warn-and-wire as first-wins. Live spec `core_plugin_lapi_failure-action` requires the action on connection identity and forbids two routers disagreeing on one Client. This ticket contradicts both on purpose: policy becomes per-router on `Bouncer`; last `New` wins TLS/transport.

```
DestBranch reload (policy or TLS only)
  New(ctx2) → SessionKey/IdentityHex changes → create() → new Client → startup=true
  old Client sleeps → grace Close

Intended
  policy-only New → same reclaim key → same Client; Bouncer holds action / Redis fail-closed / live TTL
  TLS/timeout-only New → same key → same Client → AdoptTransport (atomic.Value Store + closeIdle old)
```

Out of scope stays out: shared `DecisionStore` / cache reclaim, cursor-only key (delete Peek / union `scopes=` / replace `pkg/reclaim`), AppSec/captcha, `MetricsReporter` split.

## Decisions

- Reclaim holder stays Traefik `New` `ctx` via `reclaim.OpenWithHooks`. No `sync.Once`, no new package global, no import of published utilities `reclaim`.
- Move `lapiFailureAction`, `redisUnreachableBlock`, and `defaultDecisionTimeout` onto `Bouncer` from `config` (`lapiFailureAction` via `EffectiveFailureAction`). Delete `Client.LapiFailureAction` / `RedisUnreachableBlock` and `NewTestLapiFailureActionClient`.
- `LiveLookup` takes the live TTL as an argument; delete `c.defaultDecisionTimeout`. Accepted: two routers on one Client last-write that TTL into the shared live cache.
- Drop those three plus `StreamStartupBlock`, the three TLS fields, and `HTTPTimeoutSeconds` from `streamSettings` / `settingsFrom` **and** from live/none `identity` / `IdentityHex`.
- `StreamStartupBlock` stays write-once construct-time on `Client` (`startStream`); first incarnation keeps it. Do not make it mutable; do not put it on `Bouncer`.
- Extract LAPI HTTP + auth (including CAPI token) into a `transport` type in `client_http.go`. Store it on `Client` as `atomic.Value`. After `OpenStream` / `OpenLive` bind, `AdoptTransport(cfg)`: Store new, `closeIdle` old. Do not use `atomic.Pointer[T]`. Do not make remaining write-once Client scalars mutable; ticker flags that already mutate stay as they are.
- Remaining hash fields (intervals, Redis host/auth/db, `updateMaxFailure`, CAPI scenarios, `decisionScopeHeaders`) still first-wins via `PeekLivePrefix` warn-and-wire.
- `logInfo` gains session key + `reason`. New INFO lines for transport replace (named fields) and for a live joiner whose settings differ (`ignored` vs `adopted`). Do not raise `reclaim_put` / `reclaim_reclaim` / `reclaim_dispose` to INFO.
- Tests: same Client + no extra `startup=true` fetch after failure-action-only reload (`StreamFetches` / mock LAPI hits); same Client + new transport after TLS-only reload; two bouncers apply distinct failure actions; per-router live TTL; existing `waitStreamSessionInGrace` / `waitPluginStreamInGrace` still pass because `SessionKey` no longer moves on those knobs.
- Propose FindSpecHost: fold hash / last-wins transport into `core_plugin_middleware_instance-reclaim`; fold owner move into existing `core_plugin_lapi_failure-action`; transport file ownership into `core_plugin_lapi_connection`. Do not invent a new per-router-policy leaf.
- Usage `core_plugin_middleware.md` Language **Failure action** and the identity gotcha stay correct for DestBranch; implement / devdocsimpact update them after the apply. Explore writes no Language.
- Research: existing `ext_crowdsec_lapi_stream-cursor`, `ext_traefik_plugins_yaegi-constructor`, `ext_traefik-middleware-utilities_packages`, `ext_crowdsec_bouncers_failure-action` answer the third-party facts. No new research folder.

## Open questions

- Q: Who already owns identity (visitor address, LAPI cursor, reclaim key, failure action, LAPI HTTP/auth)?
  Decision: assumed — visitor address is `pkg/ip.GetRemoteIP` (do not re-parse `RemoteAddr`). LAPI cursor is CrowdSec’s bouncer row (hashed key + outbound IP); do not reconstruct a second cursor. Reclaim key is this plugin’s `SessionKey` / `Key`. After this change, failure action and Redis fail-closed live on `Bouncer`; LAPI HTTP/auth/token live on `transport` (`atomic.Value`). Reuse those owners.
  By: explore

- Q: Fold parts 1–2 into `core_plugin_middleware_instance-reclaim` vs a new per-router-policy leaf?
  Decision: assumed — FindSpecHost in propose folds the settings-hash / last-wins TLS delta into `core_plugin_middleware_instance-reclaim`, the owner move into existing `core_plugin_lapi_failure-action` (that spec today forbids two routers disagreeing), and the HTTP extract into `core_plugin_lapi_connection`. No new leaf.
  By: explore

- Q: Must live/none `IdentityHex` drop the same fields this PR?
  Decision: assumed — yes. `identity.go` replicates the cluster. Dropping only stream `streamSettings` would still split live/none Clients and `CachePrefix` on a policy- or TLS-only reload.
  By: explore

- Q: What is the transport type name and file?
  Decision: assumed — unexported `transport` in `pkg/lapi/client_http.go` (HTTP + header + CAPI token already live there). Field on `Client` is `atomic.Value`. Call site after Open: `AdoptTransport`.
  By: explore

- Q: Where does `StreamStartupBlock` live after it leaves the hash?
  Decision: assumed — write-once on `Client` at `startStream` only. First incarnation keeps it. Not on `Bouncer`. Not mutable after construct.
  By: explore

- Q: Two live routers, same session, different TLS — first-wins or last `AdoptTransport`?
  Decision: assumed — last `New` wins transport (ticket). Same reclaim key after the hash drop, so `PeekLivePrefix` mismatch does not fire. INFO `adopted`. Intervals / Redis / scopes still first-wins `ignored`.
  By: explore

- Q: `LiveLookup` TTL parameter shape?
  Decision: assumed — add `defaultDecisionSeconds int64` to `LiveLookup`; `Bouncer` passes `config.DefaultDecisionSeconds`. Do not keep a Client field for it.
  By: explore

- Q: Can the transport field be `atomic.Pointer[T]`?
  Decision: assumed — no. Yaegi v0.16 cannot take a generic instantiation from another package as a struct field. Use `atomic.Value` like `rangeMembership`.
  By: explore

- Q: What `logInfo` session key and `reason` values?
  Decision: assumed — stream/alone log `SessionKey`; live/none log `Key`. Existing lifecycle `reason` values stay `started|sleeping|waking|closed`. New INFO lines name transport replace and joiner `ignored` vs `adopted`. Reclaim table lines stay DEBUG.
  By: explore

- Q: Two concurrent `AdoptTransport` on one Client?
  Decision: assumed — last `Store` wins; `closeIdle` the value replaced. Do not add a mutex around remaining write-once scalars. Do not make `httpClient` a plain mutable pointer beside the `atomic.Value`.
  By: explore

- Q: When do usage docs change Language **Failure action**?
  Decision: assumed — not in explore. DestBranch text is still true. Implement / `sbs-dev-devdocsimpact` update `knowledge/devdocs/core_plugin_middleware.md` when the owner moves.
  By: explore
