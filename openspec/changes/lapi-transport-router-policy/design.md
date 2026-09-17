## Context

See `proposal.md`. On `master`, `lapi.Client` mixes stream cursor state, replaceable HTTP/cache resources, and per-router policy in one reclaim value keyed by `SessionPrefix` + hash(`streamSettings`) with 18 fields. Any policy or TLS-only reload opens a new key after grace and forces `isCrowdsecStreamStartup=true`. Explore reproduced failure-action-only hash change. Yaegi v0.16 forbids `atomic.Pointer[T]` from another package on struct fields; `rangeMembership` already uses `atomic.Value`.

## Goals / Non-Goals

**Goals:**

- Keep one reclaimed `*lapi.Client` (same cursor) when reload changes only per-router policy or transport/TLS/timeout.
- Hold per-router `lapiFailureAction`, `redisUnreachableBlock`, and live TTL on `Bouncer` (failure action via `configuration.EffectiveFailureAction`).
- Publish replaceable LAPI HTTP transport through `atomic.Value`; adopt on every successful `OpenStream` return path.
- INFO logs name session key, reason, and field-level adopt/ignore lists for transport.

**Non-Goals:**

- Shared `DecisionStore` reclaim, narrowing session key / deleting Peek APIs, AppSec/captcha, `MetricsReporter` split (debt notes).
- Shrinking live/none `IdentityHex` in this change (stream/alone resync is the driver).
- Making cursor scalars (`updateFailure`, `updateMaxFailure`, stream health flags) mutable or mutex-guarded on the ticker path.

## Decisions

1. **Settings hash composition** — Remove `lapiFailureAction`, `streamStartupBlock`, `defaultDecisionSeconds`, `redisCacheUnreachableBlock`, `httpTimeoutSeconds`, and the three TLS fields from `settingsFrom`. Remaining hash fields stay as today (intervals, Redis store, `decisionScopeHeaders`, etc.). *Alternative:* new reclaim leaf keyed only on cursor — out of scope.

2. **Policy on Bouncer** — Read the three knobs from `configuration.PluginConfig` in `bouncer.New`; wire `LiveLookup` with TTL argument; delete `LapiFailureAction()` / `RedisUnreachableBlock()` on `Client`. *Alternative:* leave on Client but exclude from hash — still exposes wrong shared semantics.

3. **`LapiTransport` type** — Own `*http.Client` and CAPI session token mutation (move off `Client.crowdsecKey` self-mutation in request path). Store `*LapiTransport` in `atomic.Value` on `Client`. Load for each HTTP call. *Alternative:* mutex around `httpClient` — rejected (ticker path must stay lock-free on cursor fields).

4. **`AdoptTransport(cfg)`** — Call from `OpenStream` after `reclaim.OpenWithHooks` + `clientFromStored` on create, bind, wake, and live joiner wired to owner key. Compare transport-relevant config; if diff, build new transport, `Store`, `closeIdle` old client. Log INFO with changed field names. Joiner with different TLS: adopt (last wins), not silent ignore. Remaining settings-hash diffs still warn-and-wire first-wins.

5. **Logging** — Extend `logInfo` with `SessionKey(cfg)` (or stable session prefix) and `reason` string; add dedicated INFO lines for transport replace and joiner settings diff. Leave `pkg/reclaim` table debug lines at DEBUG.

6. **FindSpecHost** — Three MODIFIED deltas (see `proposal.md`); no new spec folder.

## Risks / Trade-offs

- **[Shared cache TTL]** Two bouncers, different `defaultDecisionSeconds`, one cursor → last writer on TTL for shared cache keys → accepted benign trade-off.
- **[Transport last-wins]** Concurrent routers with different TLS → last adopt wins → required for rotation; INFO makes winner visible.
- **[Live/none identity lag]** Live mode still keys full identity including policy/TLS until a follow-up → documented; stream reload tests are the ticket proof.
- **[Yaegi]** Must use `atomic.Value`, not generic atomic pointer → mitigated by mirroring `rangeMembership`.

## Migration Plan

No operator config changes. Deploy plugin build; observe INFO on reload for transport adopt. Rollback = revert binary (old hash behavior returns).
