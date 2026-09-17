## Why

Traefik middleware reloads that change per-router policy or HTTP/TLS knobs today change the LAPI reclaim settings hash, so the plugin builds a new `lapi.Client`, resets stream cursor state, and pays a full CrowdSec `startup=true` resync even when the bouncer row (API key + outbound IP) is unchanged. The cursor lives on the server; those settings should not force a new incarnation.

## What Changes

- Move `lapiFailureAction`, `redisUnreachableBlock`, and live TTL (`defaultDecisionSeconds`) from `lapi.Client` to `Bouncer`; pass TTL into `LiveLookup`; remove the two policy accessors from `Client`.
- Remove those three plus `streamStartupBlock` from `streamSettings` / `settingsFrom` and from LAPI identity where duplicated.
- Extract hot-swappable LAPI HTTP transport (client + CAPI token handling) held on `Client` via `atomic.Value` (not `atomic.Pointer[T]`); `AdoptTransport(cfg)` after open with idle close of the superseded client.
- Remove TLS trio and `HTTPTimeoutSeconds` from the settings hash.
- Extend INFO lifecycle logging with session key and `reason`; INFO when transport is replaced or when a live joiner’s settings differ (adopted vs ignored field lists). Do not promote `pkg/reclaim` debug reclaim lines to INFO.

**Accepted consequences (by design):**

- Two stream routers on one cursor with different `defaultDecisionSeconds` share one cache TTL (last writer on a single lookup entry).
- Two live routers with different TLS on one cursor: last `AdoptTransport` wins (enables cert rotation; logged at INFO).
- Two routers may differ in LAPI failure action and Redis fail-closed per `Bouncer` after Part 1.

## Capabilities

### New Capabilities

- (none)

### Modified Capabilities

- `core_plugin_middleware_instance-reclaim`: Narrow the stream settings hash (drop per-router policy, startup block, HTTP timeout, TLS); keep warn-and-wire for remaining hash fields; adopt transport on join/wake/reload instead of first-wins for transport-only diffs.
- `core_plugin_lapi_failure-action`: LAPI failure action and Redis unreachable fail-closed are per-router on `Bouncer`, not shared connection identity.
- `core_plugin_lapi_connection`: Hot-swappable LAPI transport via `atomic.Value`, `AdoptTransport`, and enriched INFO traceability on connection lifecycle.

## FindSpecHost

**Verdict: both — fold into three existing leaves, no new spec id.**

| Delta | Verdict | Spec id | Confidence |
|-------|---------|---------|------------|
| Reclaim settings hash + joiner transport adopt | fold | `core_plugin_middleware_instance-reclaim` | high |
| Per-router LAPI failure action + Redis fail-closed | fold | `core_plugin_lapi_failure-action` | high |
| Hot-swappable HTTP transport + INFO traceability | fold | `core_plugin_lapi_connection` | high |

Per-router policy is not a new leaf: `core_plugin_lapi_failure-action` already owns LAPI fallback semantics; this change replaces the obsolete “on connection identity” requirement. Transport and adoption belong with LAPI connection ownership, not a fourth middleware-reclaim leaf. The intentional contradiction with today’s instance-reclaim hash list is captured as **MODIFIED** requirements there rather than splitting hash rules across a new name.

OpenSpec chat approval for the proposal was treated as granted (unattended propose).

## Impact

- `pkg/bouncer/bouncer.go`, `pkg/lapi/` (`client.go`, `client_http.go`, `client_live.go`, `client_decisions.go`, `client_stream.go`, `session.go`, `identity.go`, tests)
- `plugin.go` / `OpenStream` post-open hook for `AdoptTransport`
- Spec deltas under this change; devdocs update deferred to devdocsimpact
- Cursor write-once scalars on `Client` stay immutable; only transport uses `atomic.Value`
