# Explore

IssueKey: 2026-09-17-lapi-transport-router-policy

## Concepts

### Reclaim key layout (stream/alone)

```
SessionPrefix(cfg) = "lapi:stream:" + hashJSON(streamSession) + ":"
SessionKey(cfg)      = SessionPrefix(cfg) + hashJSON(streamSettings)
CachePrefix(cfg)     = SessionHex(cfg)   // session only, not settings hash
```

- **streamSession** (`session.go:46-54`): mode, LAPI scheme/host/path, lapiKey (CAPI machine+password in alone). Defines the CrowdSec bouncer row (hashed API key + Traefik outbound IP on the server).
- **streamSettings** (`session.go:71-90`): everything else that today enters `hashJSON(settingsFrom(cfg))` for the reclaim table key.

### streamSettings fields today (18 JSON fields)

| Field | In hash today | This PR removes from hash |
|-------|---------------|---------------------------|
| `capiScenarios` | yes | no |
| `updateIntervalSeconds` | yes | no |
| `metricsUpdateIntervalSeconds` | yes | no |
| `updateMaxFailure` | yes | no |
| `lapiFailureAction` | yes | **yes** → Bouncer |
| `streamStartupBlock` | yes | **yes** (read only at stream start) |
| `defaultDecisionSeconds` | yes | **yes** → Bouncer / LiveLookup arg |
| `httpTimeoutSeconds` | yes | **yes** → hot-swappable transport |
| `redisCacheEnabled` | yes | no |
| `redisCacheHost` | yes | no |
| `redisCacheReadHosts` | yes | no |
| `redisCachePassword` | yes | no |
| `redisCacheDatabase` | yes | no |
| `redisCacheUnreachableBlock` | yes | **yes** → Bouncer |
| `lapiTlsInsecureVerify` | yes | **yes** → transport |
| `lapiTlsCa` | yes | **yes** → transport |
| `lapiTlsCert` | yes | **yes** → transport |
| `decisionScopeHeaders` | yes | no |

After the PR, **10** settings fields remain in the hash (plus the unchanged session prefix).

Live/none still use `Key(cfg) = "lapi:" + IdentityHex(cfg)` where `identity` (`identity.go:19-44`) mirrors almost all connection knobs including failure action, TTL, TLS, and Redis unreachable — **not** narrowed in this ticket’s stream-focused story; propose should decide whether live/none identity shrinks in parallel.

### OpenStream flow vs Close / transport

```
plugin.New → lapi.OpenStream(ctx, cfg, …)
                 │
                 ├─ joinerKey := SessionKey(cfg)
                 ├─ PeekLivePrefix(SessionPrefix) → live sibling?
                 │     different SessionKey → warnWiredToOwner, bindKey = live.Key (first-wins)
                 └─ reclaim.OpenWithHooks(bindKey, create=New+clientHooks)
                        → bind | wake | create
                 → clientFromStored

Client.Close → stop tickers → drainMetrics → closeIdle(httpClient) → cache Close
Client.Sleep → stop tickers only (HTTP + cursor kept)
```

- **Joiner hook today:** `OpenStream` (`session.go:226-238`) — when a **live** slot exists under `SessionPrefix` with a **different** `SessionKey`, the joiner binds the **owner’s** key and `warnWiredToOwner` logs `ignoredSettings` via `settingsDiff`. There is **no** callback to mutate the stored `*Client`; joiner policy/TLS/timeouts are silently dropped (first-wins).
- **AdoptTransport (desired):** not present. Natural call site: **after** `reclaim.OpenWithHooks` + `clientFromStored` in `OpenStream`, when the joiner’s transport-relevant config differs from what the stored client uses — publish new `*http.Client` via `atomic.Value`, `closeIdle` on the replaced client (`client_http.go:34`, used from `Close` at `client.go:220`). Same-key **Wake** after reload should also adopt transport when TLS/timeout changed but hash no longer splits the key.
- **plugin.go** (`plugin.go:53-57`) only calls `OpenStream`; no post-open adoption.

### Client innards relevant to the split

- Per-router policy on `Client` today: `lapiFailureAction`, `defaultDecisionTimeout`, `redisUnreachableBlock` (`client.go:57-61`) with accessors at `351-358`; bouncer is the only consumer of the accessors (`bouncer.go` per requirement).
- **Yaegi-safe hot swap:** `rangeMembership atomic.Value` (`client.go:66`) — store `*decisionscope.RangeMembership` with `Load`/`Store`; **do not** use `atomic.Pointer[T]` from another package as a struct field (Yaegi v0.16).
- **Write-once cursor scalars:** `handleStreamTicker` (`client_stream.go:48-63`) reads `updateFailure`, `updateMaxFailure`, `isCrowdsecStreamHealthy` without `Client.mu`; `startTicker` spawns `go work()` per tick. This PR must **not** make those fields mutable; moved knobs leave `Client`; transport uses `atomic.Value` only.

### Spec vs intentional behavior change

Live spec `openspec/specs/core_plugin_middleware_instance-reclaim/spec.md` requires LAPI failure action, TLS extras, and HTTP timeout **in** the settings hash and **warn-and-wire first-wins** when a live joiner differs. Parts 1–2 of this ticket deliberately contradict that (per-router policy off hash; **last** transport wins on adopt). Resolve via **FindSpecHost in propose** (fold vs new leaf).

### Test seams

- `waitStreamSessionInGrace` (`zzz_session_test.go:187-200`): polls `reclaim.Peek(SessionKey(cfg))` until `Holders==0 && Sleeping`. Still valid if `SessionKey` stops including failure/TLS — helpers key off the **post-change** `SessionKey` in tests.
- `waitPluginStreamInGrace` (`zzz_plugin_test.go:457-470`): same loop at plugin level. Unchanged contract.
- Existing proof that **any** settings delta opens a new incarnation after grace: `TestOpenStream_GraceSnapshotChangeStopsOldTickerFirst` (metrics interval 1 → 600) — `first != second`, new `StreamFetches`.

### Devdocs consumed

- `knowledge/devdocs/index.md` → `core_plugin_middleware.md` (OpenStream/OpenLive, reclaim keys, failure action on LAPI Client).
- No new devdocs packet in explore; **stale usage** noted: middleware doc still says LAPI failure action is on LAPI Client identity — devdocsimpact should update after implement.

## Decisions

1. **Part 1 scope:** Move `lapiFailureAction`, `redisUnreachableBlock`, and live TTL (`defaultDecisionSeconds`) onto `Bouncer`; pass TTL into `LiveLookup`; strip four fields from `streamSettings` / `settingsFrom` (including `StreamStartupBlock`).
2. **Part 2 scope:** Extract LAPI HTTP transport (client + CAPI token mutation today in `client_http.go:71`) into a value held in `Client` via `atomic.Value`; implement `AdoptTransport(cfg)` with idle close of superseded client; remove TLS trio + `HTTPTimeoutSeconds` from settings hash.
3. **AdoptTransport wiring:** Implement in `OpenStream` (and consider `OpenLive` if identity narrows later) immediately after successful open/bind/wake, before returning to `plugin.New`.
4. **Logging:** Extend `logInfo` with session key + `reason`; INFO on transport replace and on live joiner settings mismatch (ignored vs adopted lists); do not promote `pkg/reclaim` debug reclaim lines to INFO.
5. **Cursor scalars:** Leave `updateFailure`, `updateMaxFailure`, `isCrowdsecStreamStartup`, `isCrowdsecStreamHealthy` write-once; no mutex on ticker path.
6. **Accepted trade-offs:** Shared cache TTL last-writer when routers differ on `defaultDecisionSeconds`; distinct per-router failure action and Redis fail-closed after Part 1.
7. **Out of scope (binding):** DecisionStore reclaim, narrow session key / delete Peek APIs, AppSec/captcha, MetricsReporter split — already `knowledge/debt/` + `issues.md`.

## Open questions

- Q: Where exactly should `AdoptTransport` run relative to reclaim `Open` / warn-and-wire?
  Decision: assumed — call from `OpenStream` after `clientFromStored` on every successful return path (create, bind, wake); on live joiner wired to owner’s key, adopt joiner transport if transport fields differ; log adopted vs ignored field names at INFO.
  By: explore

- Q: Should live/none `identity` / `OpenLive` drop failure action, TTL, TLS, and Redis unreachable from `IdentityHex` in the same change?
  Decision: assumed — stream/alone resync is the ticket driver; narrow live/none identity only if propose tasks stay small; otherwise follow-up note. Minimum deliverable is stream `SessionKey` + `OpenStream` behavior and tests named in the ticket.
  By: explore

- Q: Spec `core_plugin_middleware_instance-reclaim` contradicts per-router policy and last-wins transport — fold or new leaf?
  Decision: assumed — defer to **FindSpecHost in propose**; explore records the tension only; implement must update the chosen spec leaf(s) when propose names them.
  By: explore

- Q: CAPI `crowdsecKey` auto-mutation (`client_http.go:71`) — transport or cursor identity?
  Decision: assumed — move with transport (ticket Part 2); cursor identity stays lapiKey / machine credentials on `Client` fields used for session prefix only.
  By: explore

- Q: Devdocs say failure action lives on LAPI Client — update when?
  Decision: assumed — **devdocsimpact** after implement; explore does not write packets.
  By: explore

- Q: Two routers live with different `lapiFailureAction` on same cursor — behavior after Part 1?
  Decision: resolved — each `Bouncer` applies its own `EffectiveFailureAction`; shared `*lapi.Client` no longer exposes `LapiFailureAction()`.
  By: explore

- Q: Reload changing only TLS while another router holds the live slot — transport winner?
  Decision: assumed — last `AdoptTransport` from a joiner or reload wins (ticket Part 2); INFO logs field diff; contradicts current spec first-wins until spec is updated in propose/implement.
  By: explore

- Q: Does changing only `lapiFailureAction` today force a new `*lapi.Client` and stream resync?
  Decision: resolved — yes for **sleeping-then-new-open** path: different `SessionKey` → new reclaim entry → `New` → `isCrowdsecStreamStartup=true`. Live joiner with different failure action today **warn-and-wires** to owner (same pointer, joiner action ignored). Measured: ephemeral `TestFailureActionAloneChangesSessionKey` (explore-only, not committed) + `settingsFrom` includes `LapiFailureAction`; `TestOpenStream_GraceSnapshotChangeStopsOldTickerFirst` proves settings-only delta after grace creates distinct clients.
  By: explore
