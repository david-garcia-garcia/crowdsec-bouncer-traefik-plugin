# Explore
IssueKey: 2026-09-06-plugin-lifecycle-lapi

## Concepts

**LAPI stream session (CrowdSec):** `GET /v1/decisions/stream` advances `stream_cursor` on the **bouncer database row** (hashed `X-Api-Key` + client IP as LAPI sees it). Not per HTTP client, not per `scopes=` query, not per Traefik middleware name. Two `startup=false` clients on the same row share and race that cursor. Owner: `knowledge/research/ext_crowdsec_lapi_stream-cursor/notes.md`.

**Reclaim identity (this plugin):** FNV of JSON `identityFrom` (`pkg/crowdsecconnection/identity.go`). Includes intervals, Redis, TLS, AppSec, failure action. Does **not** include `decisionScopeHeaders`. `reclaim.Open` is one incarnation per that hash. Traefik `New` ctx is the holder (`pkg/reclaim`, `std_go_reclaim`).

**Stream poller:** `startStream` → ticker → `handleStreamCache` → `streamQuery` (`startup=` + `scopes=`). Cache and `range-index` prefix = `IdentityHex`. Separate hashes ⇒ two pollers, two prefixes, one LAPI row.

**Opposite bug:** same hash, different `decisionScopeHeaders` ⇒ first `New` wins `scopes=`. E2e already uses `BOUNCER_KEY_TRAEFIK_SCOPES` because a second poller on the test key would steal deltas.

```
  Traefik process
  ┌────────────── /stream  metrics=1  ──┐
  │  Key(hash A) → Connection A          │      CrowdSec LAPI
  │    ticker ── GET /stream?startup=    │      bouncer row (key+IP)
  │    cache prefix A                    ├──►   one stream_cursor
  ├────────────── /trusted metrics=600 ──┤      last writer wins
  │  Key(hash B) → Connection B          │
  │    ticker ── GET /stream?startup=    │
  │    cache prefix B                    │
  └──────────────────────────────────────┘
```

## Decisions

- Do not key reclaim by middleware name. Do not add `sync.Once`. Keep `reclaim.Open(ctx, …)` and Traefik constructor ctx as the holder.
- Do not treat matching e2e `metricsUpdateIntervalSeconds` as the product fix.
- Do not start a second stream poller because two intervals were requested.
- Do not first-win a second config onto a connection whose Redis prefix or `scopes=` already diverged — fail before bind, or share only when the session snapshot matches.
- Isolated backends (including different header-scope maps) keep needing a **second bouncer key**. That is already the scopes e2e pattern.
- Check session occupancy **before** `reclaim.Open`. `Open` always binds `ctx`; a fail-after-bind would leak a holder (`pkg/reclaim/table.go`).
- Fail `New` only when another **live** constructor ctx already holds the session with a different snapshot (two middlewares both up). A Traefik reload that cancelled the previous holders (orphan/grace) MUST dispose and create with the new knobs — including a fixed TLS cert. Do not pin the first cert for the life of the process.

## Reproduction

Ran throwaway `go test -count=1 -v -run TestRepro_ .` on dest (deleted after; not committed).

- Same LAPI host+key, stream mode, `MetricsUpdateIntervalSeconds` 1 vs 600: `Key()` differs; two `New` with live ctx; two `CrowdsecConnection`; `StreamFetches=1/1`; mock LAPI stream hits=2. **Reproduced.**
- Same, only `UpdateIntervalSeconds` 5 vs 30: `Key()` differs. **Reproduced.**
- Same key, `decisionScopeHeaders` empty vs `Country=CF-IPCountry`: `Key()` **equal** today. Opposite bug confirmed.

Did not re-run Docker e2e (compose currently forces `/trusted` metrics=1). Unit path is the reclaim split the ticket names.

## Human sketch (2026-09-06)

- One Stream incarnation per LAPI key (first middleware owns knobs), not per middleware name.
- Second middleware same key: warn in logs, wire to the existing Stream (first-wins extras).
- Dynamic config change: stop the old Stream immediately (skip reclaim grace) so the new Stream does not overlap on the cursor.

Keep reclaim grace when the snapshot is **unchanged** (Traefik reload reuse). Eager-stop only when replacing the session incarnation.

## Recommended shape (for propose, pending human)

Stream **session** (the unique poller resource) = LAPI scheme+host+path + lapiKey, or CAPI machine+password in alone, plus LAPI client-cert identity when that is how the bouncer authenticates.

`scopes=` is **not** a second LAPI session. Different `decisionScopeHeaders` on the same URL+key still share one CrowdSec cursor. Putting scopes in the FNV hash (PR #18) stops first-win by starting a **second poller** — that is the same steal-deltas bug. Treat scopes mismatch as a **conflict** on the existing session (fail `New`), not as two sessions.

Settings snapshot on the session (must match or fail): `UpdateIntervalSeconds`, `MetricsUpdateIntervalSeconds`, Redis*, `HTTPTimeoutSeconds`, `LapiFailureAction`, `UpdateMaxFailure`, `StreamStartupBlock`, `DefaultDecisionSeconds`, AppSec client fields, TLS that is not already in the session, `decisionScopeHeaders` (normalized). Error names both middleware names and the fields that differ. Store the first `New` name on the connection for that message.

Reclaim key = session (not the leftover extras). Redis / range-index prefix follows the session. Live/none/appsec do not take a stream session; two live connections on one key stay OK for `?ip=` lookups.

`reclaim.Open` stays. Session registry lives in `pkg/crowdsecconnection` and is consulted from `plugin.go` `New` before Open.

Spec `core_plugin_middleware_instance-reclaim`: keep “same session ⇒ one ticker”; replace “disagree on interval ⇒ two connections” with config error when URL+key match. Usage packets after human yes: `core_plugin_middleware.md` gotcha, `build_e2e_real.md` (matching metrics labels is not the long-term story), `core_cache_client.md` prefix.

## Open questions

- Q: Fail `New` on same-session conflicting knobs, or reclaim the first connection and ignore extras?
  Decision: assumed — human prefers warn+wire (first-wins) over fail, with the owner middleware and ignored knobs in the log. Share the one Stream. Scopes mismatch is still the dangerous first-win (Country not in `scopes=`). Reload with a new snapshot and no other live holder: replace, do not warn-and-keep-old.
  By: explore

- Q: On config refresh, skip reclaim grace so old and new streams do not both poll?
  Decision: resolved — last holder Sleep()s tickers; Open on the same SessionKey during grace Wake()s (startup=false). Snapshot change is a new SessionKey (session prefix + settings hash); the old sleeper dies on grace Close. No ReplaceSleeping. Callers do not Close slots.
  By: implement

- Q: Can an operator fix a wrong LAPI TLS cert (or any session snapshot knob) without restarting the Traefik process?
  Decision: resolved — yes. Reload cancels the previous constructor ctx; that is a new SessionKey, not a concurrent conflict. Fail only while another live middleware still holds (PeekLivePrefix warn-and-wire). Reclaim grace is 10s (`pkg/reclaim` `DefaultGrace`); that is a dispose delay, not a process restart.
  By: implement

- Q: Does the session key include LAPI TLS client certificate (keyless TLS bouncer) in addition to `lapiKey`?
  Decision: resolved — no. TLS extras are the settings snapshot (in SessionKey’s hash, not SessionPrefix). PeekLivePrefix + streamOwner detect another live middleware. Sleeping + different snapshot → Open a new key. Two live middlewares with different certs warn-and-wire.
  By: implement

- Q: Are different `decisionScopeHeaders` a different stream session or a conflict on one session (URL+key)?
  Decision: assumed — conflict on one session. LAPI cursor is the bouncer row, not `scopes=`. Second key remains the isolation mechanism. Do not land PR #18’s “scopes in identity ⇒ two pollers” as the product fix.
  By: explore

- Q: Live/none (and AppSec-only) two usage-metrics tickers on the same bouncer key — fail, share one reporter, or leave as today?
  Decision: assumed — leave live/none/appsec as today (two connections OK). Stream/alone metrics ticker rides the one session connection, so fail-on-conflict also prevents two stream metrics POSTs. Do not add a second uniqueness plane in this change.
  By: explore

- Q: Relationship to OPEN PR #18 (`2026-09-05-scope-headers-identity`)?
  Decision: assumed — this ticket supersedes putting scopes in the reclaim hash as a splitter. #18 can close or rebase onto fail-on-conflict. Note on `issues.md`.
  By: explore

- Q: Who owns stream-session identity (cursor / bouncer row)?
  Decision: assumed — CrowdSec LAPI owns the cursor on the bouncer row. This plugin reuses that: at most one in-process poller per URL+key (and TLS cert). Do not invent a second cursor. Request client IP stays `pkg/ip.GetRemoteIP`.
  By: explore

- Q: Do two Traefik processes with in-memory cache and the same LAPI key steal deltas?
  Decision: assumed — out of this change. Same key + same LAPI-visible client IP already share one bouncer row (pre-existing). Distinct source IPs get distinct rows (`ext_crowdsec_lapi_stream-cursor`). Shared Redis + `"updated"` lease is the multi-instance store. In-process uniqueness does not create or fix the NAT-to-one-IP case.
  By: explore

- Q: Reclaim key session-only (ReplaceSleeping on snapshot change) or session prefix plus settings hash with PeekLivePrefix?
  Decision: resolved — human chose SessionKey = SessionPrefix + settings hash. PeekLivePrefix finds a live sibling on the CrowdSec row. Drop ReplaceSleeping / discardSleeping.
  By: implement
