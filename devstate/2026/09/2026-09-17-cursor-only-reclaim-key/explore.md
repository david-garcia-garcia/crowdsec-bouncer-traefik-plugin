# Explore

## Concepts

```
CrowdSec LAPI (one bouncer row)
  hashed X-Api-Key + outbound IP LAPI sees
  stream_cursor / last_pull
        ▲
        │  GET /v1/decisions/stream?startup=&scopes=
        │  scopes= filters the same cursor (id_gt), not a second row
        │
this process (Traefik New per router)
  reclaim Table  (ProcessGrace 30s; New ctx is the holder)
        │
        ├─ lapi.Client     key today: SessionPrefix + hash(streamSettings)
        │                  siblings: PeekLivePrefix + warn-and-wire
        │                  sleeper retitle: Peek(bindKey) when Holders==0
        │
        └─ DecisionStore   key: decisionstore: + SessionHex + hash(storeParams)
                           Redis prefix: SessionHex (every mode; CachePrefix gone)
```

**Cursor row** is CrowdSec’s fact: one `stream_cursor` on the bouncer row selected by SHA-512 of `X-Api-Key` plus the IP LAPI sees (this process’s outbound address). Plugin settings do not pick that row. `scopes=` is a filter of the same cursor. Owner: `knowledge/research/ext_crowdsec_lapi_stream-cursor/`.

**SessionHex** is this process’s proxy for that row: FNV-64a of mode + LAPI scheme/host/path + lapiKey (CAPI machine+password in alone). It is already the Redis prefix and the DecisionStore stem. It does not reconstruct outbound IP.

**Today’s stream Open key** (`SessionKey`) is `lapi:stream:` + SessionHex + `:` + hash of `streamSettings` (intervals, Redis, `updateMaxFailure`, CAPI scenarios, `decisionScopeHeaders`). A live joiner with a different hash is `PeekLivePrefix(SessionPrefix)` then warn-and-wire onto the sibling slot. A sleeping leftover with a different hash is a new key; `Peek(bindKey)` only retitles `streamOwner` when `Holders == 0`.

**Today’s live/none Open key** (`Key`) is `lapi:` + `IdentityHex`. That payload keeps intervals, CAPI scenarios, `updateMaxFailure`, and Redis, and already omits `decisionScopeHeaders`.

**DecisionStore key** is already cursor-shaped plus Redis: `decisionstore:` + SessionHex + `:` + hash(`storeParams`). Two Clients that disagree only on intervals or header maps already share one store.

**Write-once `decisionScopeHeaders`** is set in `lapi.New` and read by `streamQuery` / `storeStreamDecision`. Out of scope: turning that scalar into a mutable field, and `atomic.Pointer[T]`.

**Peek / View** exist so a sidecar can read unexported table `items`. Upstream utilities `reclaim` v1.0.3 (`950b08d`) has `New`, `Table`, `Open`, `OpenWithHooks`, `OpenTyped` — no Peek. AfterFunc grace (Yaegi `_select` hang) is already in both copies. Sisters (geoblock, modsecurity) import utilities, hold a table, pass Traefik `New` ctx, and do not use `sync.Once` or Peek.

**OpenTyped** wraps `OpenWithHooks` and still takes `func() (any, Hooks, error)`. It types the return; it does not remove hooks-as-function-values (Yaegi panics asserting a foreign concrete type).

## Decisions

- Stream Open key becomes cursor + Redis, same payload family as `StoreKey`: SessionHex plus `storeParamsFrom` (enabled/host/read hosts/password/database). Drop intervals, `updateMaxFailure`, CAPI scenarios, and `decisionScopeHeaders` from the Client hash. Align with the store; do not drop Redis (that would share one Client across Redis hosts).
- Live/none Open key drops the same remaining fields as stream (intervals, CAPI scenarios, `updateMaxFailure`). Keep Redis. Keep `lapi:` prefix. `IdentityHex` stays exported if callers/specs still name it; it is no longer the live Open suffix.
- Keep distinct table prefixes: `lapi:stream:`, `lapi:`, `decisionstore:`, `appsec:`. Do not reuse `StoreKey` as the Client key string (one process table, several value types).
- Delete `Peek`, `PeekLivePrefix`, and `View` (production, shim, `zzz_peek_test.go`). After one cursor+Redis key, `Open` of that key Wakes the sleeper. Keeping `PeekLivePrefix(SessionPrefix)` would warn-and-wire a different-Redis joiner onto the first live slot and break store isolation. Sleeper `streamOwner` retitle has no remaining warn-and-wire job; no replacement API.
- Interval / CAPI / `updateMaxFailure` mismatch on a live sibling is silent first-wins (create already wrote those scalars). Out of scope to union them. Do not keep Peek only to log `ignored`.
- `scopes=` and the store header-scope filter read a Client-owned live-router union, not the write-once `decisionScopeHeaders` map. New registry on the Client; register after a successful `OpenStream` bind with this `New` ctx and this router’s normalized headers; drop on ctx Done. Traefik `New` ctx is the holder. Do not use `sync.Once` or a package global.
- Leave `decisionScopeHeaders` write-once at `New`. Do not convert it. CAPI still omits `scopes=`. Live/none still pass scopes per `LiveLookup` from the Bouncer map. AppSec reclaim key is unchanged.
- Import utilities `reclaim` v1.0.3 and delete the local `table.go` fork. Keep the local shim only: `Default`, `ProcessGrace` 30s, `Open` / `OpenWithHooks`, `ResetForTest` / `ResetForTestWith`. Do not take `OpenTyped` (it does not remove hooks-as-funcs). AppSec stays on `OpenWithHooks` + type assert.
- Upgrade: `SessionHex` and store Redis params do not change. Existing Redis keys stay reachable. Changing the Client Open string only renames an in-process table key. Document that; do not migrate Redis. `#66` already prefixes Redis with `SessionHex`; there is no `CachePrefix`.
- Specs to rewrite in propose: `core_plugin_lapi_reclaim-key` (first-wins hash, `PeekLivePrefix`, warn-and-wire, sleeping snapshot-change opens a new key), `core_cache_client_decision-store` (first-wins `scopes=` / warn-and-wire stay on the Client key), plus stream-lease / middleware-bouncer only where they still require Peek or a settings-hash sibling. Debt file closes on implement, not prepare.
- Usage packets still describe DestBranch (`std_go_reclaim` forbids the utilities import because of Peek; `core_plugin_lapi_reclaim-key` still names the settings hash). Do not rewrite them to the future here. Implement / `sbs-dev-devdocsimpact` update them after apply. No new Language term (union owner does not exist yet; do not invent).
- Third-party facts already in `ext_crowdsec_lapi_stream-cursor` and `ext_traefik-middleware-utilities_packages`. No research write this phase.

## Open questions

- Q: Who already owns CrowdSec cursor-row identity (hashed key + the IP LAPI sees), and who owns the visitor address?
  Decision: resolved — CrowdSec LAPI owns the bouncer row and outbound `ClientIP()`. This plugin does not reconstruct that hop. In-process proxy is `SessionHex` / `streamSession`. Visitor address owner is `pkg/ip.GetRemoteIP`. Do not parse `RemoteAddr`. Do not put a peer library’s reconstructed IP on the reclaim key.
  By: explore

- Q: Is `Peek(bindKey)` sleeper retitle still required after one cursor+Redis key, and what replaces it?
  Decision: resolved — not required. `Open` of that same key Wakes the sleeper. Delete Peek. No replacement inspect API. Tests that asserted via Peek use pointer equality on the `Open` return or `ResetForTest`.
  By: explore

- Q: How to hold a live-router `scopes=` union without mutating write-once `decisionScopeHeaders`?
  Decision: assumed — new Client-owned registry (scope names from each live `New`’s normalized headers), keyed by that constructor ctx; register after bind; unregister on ctx Done; `streamQuery` and `storeStreamDecision` snapshot the union under the existing Client mutex. Leave the write-once map as first-create residue. Not `atomic.Pointer[T]`. Not a package global.
  By: explore

- Q: Does live/none `Key` drop the same remaining fields as stream (ticket names `identity.go`; store already uses SessionHex + Redis)?
  Decision: assumed — yes. Live Open key is `lapi:` + SessionHex + Redis `storeParams` hash (same remaining drop as stream). Intervals no longer split live Clients that already share a store.
  By: explore

- Q: Exact Client key string versus `StoreKey` (`lapi:stream:` vs `decisionstore:` prefix)?
  Decision: assumed — keep `lapi:stream:<SessionHex>:<storeParamsHash>` and `lapi:<SessionHex>:<storeParamsHash>`. Do not copy the `decisionstore:` prefix. Same hash payload family as the store; different type prefix on the shared table.
  By: explore

- Q: Does Redis stay on the Client key (store alignment) or drop with the CrowdSec-row settings?
  Decision: resolved — Redis stays. Ticket tension: dropping it would share one Client across Redis hosts. Store already isolates by Redis. Sleeping Redis-host change remains a new key (spec “does not overlap pollers” still holds). Sleeping interval/CAPI/scopes change Wakes the same slot.
  By: explore

- Q: Upgrade: if SessionHex and store Redis params stay, existing Redis keys stay reachable. If either changes, they become unreachable. What do we document?
  Decision: resolved — SessionHex and store Redis params stay. Document: Redis keys unchanged versus DestBranch; only the in-process Client Open string changes; no key migration.
  By: explore

- Q: Take `OpenTyped` to drop hooks-as-funcs?
  Decision: resolved — no. `OpenTyped` still takes `func() (any, Hooks, error)` (`reclaim/opentyped.go` at utilities v1.0.3). Leave `OpenWithHooks` + `clientHooks` / AppSec inline funcs. Say why in propose.
  By: explore

- Q: When the live-router union grows after the CrowdSec cursor has advanced, do we send `startup=true` so the new scopes are backfilled?
  Decision: assumed — no. LAPI `scopes=` is a filter of `id_gt`; a newly added scope misses decisions already past the cursor until a later incarnation `startup=true`. Out of scope to auto-startup. Document the miss window.
  By: explore

- Q: When the union shrinks, do we sweep stale header-scope cache keys?
  Decision: assumed — no. Bound the ask. Stale Country/AS keys expire with TTL or die with the store incarnation. Do not sweep on unregister.
  By: explore

- Q: After Peek is gone, is any other utilities `reclaim` v1.0.3 surface missing (would force a fork)?
  Decision: resolved — no. Needed surface is `New` / `Table` / `Open` / `OpenWithHooks` / Hooks / AfterFunc grace. `Default` / `ProcessGrace` / test Reset stay in the local shim. Missing Peek is expected, not a blocker.
  By: explore
