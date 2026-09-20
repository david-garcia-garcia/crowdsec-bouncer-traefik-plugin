## Context

See proposal.md Why. DestBranch `SessionKey` is `lapi:stream:` plus `SessionHex` plus `hash(storeParamsFrom)` (`pkg/lapi/session.go`). `OpenStream` / `OpenLive` call `OpenDecisionStore` on the constructor ctx, then `reclaim.OpenWithHooks` for the Client (`pkg/lapi/session.go`). `Client.Close` does not Close the store (`pkg/lapi/client.go`). Join vs Wake vs create is already `reclaim.OpenWithHooks` table state (`std_go_reclaim_context-lease`); there is no `Peek`. Live/none `Key` still hashes Redis and `MetricsUpdateIntervalSeconds` (`pkg/lapi/identity.go`) — this change does not drop that. Mode stays in `SessionHex`, so stream and live never share a Client or a `MetricsReporter`. Header maps already union via `liveHeaderScopes` (`pkg/lapi/liveheaderscopes.go`). `AdoptTransport` last-wins TLS/timeout (`pkg/lapi/client_http.go`). Explore decisions in `devstate/2026/09/2026-09-20-lapi-session-subscribe/explore.md` are binding.

## Goals / Non-Goals

**Goals:**

- Stream/alone Open key = LAPI session (`SessionHex` only)
- Subscribe / Wake / create from table state; first-wins session-owned knobs with WARN
- Holder names as a ctx-keyed set; store as Client child; Close hook Closes store
- Operator WARN / first-create INFO / README as specified

**Non-Goals:**

- Live/none `Key` dropping Redis or metrics interval
- One `MetricsReporter` across stream and live
- Fail `New`, Peek, host-alone key, middleware-name reload
- Memory↔Redis migrate; Redis key migration; two-process reclaim
- Usage-packet rewrites (implement / devdocsimpact)

## Decisions

1. **Stream Open key** = `lapi:stream:` + `SessionHex`. Drop `hashJSON(storeParamsFrom)` and the trailing hash separator. Alternative: keep Redis on the key — rejected (false isolation). Alternative: LAPI host alone — rejected (two keys on one host stay two Clients).

2. **Join classification** = whether the `OpenWithHooks` `create` closure ran (local flag). `create` → first-create INFO. `!created` → compare residue and WARN on mismatch. Alternative: Peek — rejected. Alternative: middleware name as reload signal — rejected (Traefik `New` is per router).

3. **Store construction** = `create()` calls `decisionstore.NewMemory` / `NewRedis` with `keyPrefix = SessionHex`. Stop `OpenDecisionStore` from `OpenStream` / `OpenLive`. If `decisionstore.Open` / `lapi.OpenDecisionStore` become unused, delete them. `StoreKey` MAY stay as a helper. On `create()` error after store New, Close the store before return (no sibling reclaim to clean it). Alternative: keep sibling store Open — rejected (zombie store on stream Redis drop).

4. **Close vs Sleep** = Client Close Closes the child store. Sleep/Wake keep store and CrowdSec cursor (`startup=false` on Wake). Redis YAML change on Wake WARNs and keeps the live store; no migrate.

5. **Residue** = capture at `create()`: Redis enabled/host/password/database/read hosts, `updateIntervalSeconds`, `metricsUpdateIntervalSeconds`, `updateMaxFailure`, CAPI scenarios. Compare on `!created`. WARN lists field names (never `redisCachePassword` value) plus distinct holder names plus “isolation needs a second bouncer API key”.

6. **Holder names** = Client-owned map keyed by constructor ctx → Traefik `name`, register after successful Open (stream and live), `context.AfterFunc` unregister, same shape as `liveHeaderScopes`. WARN prints the distinct-name set. Not `ownerName`.

7. **Live Key** stays Redis + metrics interval. Live Redis disagreement still Opens a sibling Client (not a stream subscribe WARN). Live metrics-interval split constructs two child stores (memory isolates; Redis still shares `SessionHex` keys). Do not keep a sibling store Open to preserve the old share.

8. **Logs** = first-create `reason=started` INFO names process-wide stream/metrics ownership (`MsgConnectionStarted` or the same INFO line). Transport replace / joiner adopted stay INFO. Do not log `ignored` INFO for session-owned knobs.

9. **README** = shared-session Note: one key in this instance = one ticker + one metrics window; Redis/interval disagreements ignored, not isolated; two processes are two tickers (docs only). Stream+live on one key still two windows — one sentence, no shared reporter.

## Risks / Trade-offs

- [Two Traefik processes still steal one CrowdSec cursor] → Docs only. Reclaim is process-local.
- [Live still isolates by Redis while stream ignores it] → Accepted this ticket. Do not invert live `Key` tests except store-as-child side effects.
- [Stream+live POST two metrics windows to one CrowdSec row] → Keep mode in `SessionHex`. Isolation remains a second bouncer key.
- [WARN could leak Redis password] → Field name only.
- [Failed `create()` leaks a Redis pool] → Close the store on the error path before `create()` returns.
- [Live metrics-interval split no longer shares a reclaim Store] → Accepted. Redis keys still meet at `SessionHex`.

## Migration Plan

- In-process: stream Open string drops the Redis suffix; old Redis-suffixed slots die with grace. Joiners bind the session key.
- Redis: logical keys stay under `SessionHex`. No key migration. No memory↔Redis migrate on Wake.
- Rollback: revert the change; stream keys include the Redis hash again.

## Open Questions

None. Explore rows in `devstate/2026/09/2026-09-20-lapi-session-subscribe/explore.md` stand.
