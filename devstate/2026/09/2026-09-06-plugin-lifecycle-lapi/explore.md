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

## Reproduction

Ran throwaway `go test -count=1 -v -run TestRepro_ .` on dest (deleted after; not committed).

- Same LAPI host+key, stream mode, `MetricsUpdateIntervalSeconds` 1 vs 600: `Key()` differs; two `New` with live ctx; two `CrowdsecConnection`; `StreamFetches=1/1`; mock LAPI stream hits=2. **Reproduced.**
- Same, only `UpdateIntervalSeconds` 5 vs 30: `Key()` differs. **Reproduced.**
- Same key, `decisionScopeHeaders` empty vs `Country=CF-IPCountry`: `Key()` **equal** today. Opposite bug confirmed.

Did not re-run Docker e2e (compose currently forces `/trusted` metrics=1). Unit path is the reclaim split the ticket names.

## Recommended shape (for propose, pending human)

Stream **session** (the unique poller resource) = LAPI scheme+host+path + lapiKey, or CAPI machine+password in alone, plus LAPI client-cert identity when that is how the bouncer authenticates.

`scopes=` is **not** a second LAPI session. Different `decisionScopeHeaders` on the same URL+key still share one CrowdSec cursor. Putting scopes in the FNV hash (PR #18) stops first-win by starting a **second poller** — that is the same steal-deltas bug. Treat scopes mismatch as a **conflict** on the existing session (fail `New`), not as two sessions.

Settings snapshot on the session (must match or fail): `UpdateIntervalSeconds`, `MetricsUpdateIntervalSeconds`, Redis*, `HTTPTimeoutSeconds`, `LapiFailureAction`, `UpdateMaxFailure`, `StreamStartupBlock`, `DefaultDecisionSeconds`, AppSec client fields, TLS that is not already in the session, `decisionScopeHeaders` (normalized). Error names both middleware names and the fields that differ. Store the first `New` name on the connection for that message.

Reclaim key = session (not the leftover extras). Redis / range-index prefix follows the session. Live/none/appsec do not take a stream session; two live connections on one key stay OK for `?ip=` lookups.

`reclaim.Open` stays. Session registry lives in `pkg/crowdsecconnection` and is consulted from `plugin.go` `New` before Open.

Spec `core_plugin_middleware_instance-reclaim`: keep “same session ⇒ one ticker”; replace “disagree on interval ⇒ two connections” with config error when URL+key match. Usage packets after human yes: `core_plugin_middleware.md` gotcha, `build_e2e_real.md` (matching metrics labels is not the long-term story), `core_cache_client.md` prefix.

## Open questions

- Q: Fail `New` on same-session conflicting knobs, or reclaim the first connection and ignore extras?
  Decision: assumed — fail `New`. Silent ignore is how this bug was born. Share only when the settings snapshot matches. Traefik `New` may return error; that middleware/router fails to build (`ext_traefik_plugins_yaegi-constructor`).
  By: explore

- Q: Are different `decisionScopeHeaders` a different stream session or a conflict on one session (URL+key)?
  Decision: assumed — conflict on one session. LAPI cursor is the bouncer row, not `scopes=`. Second key remains the isolation mechanism. Do not land PR #18’s “scopes in identity ⇒ two pollers” as the product fix.
  By: explore

- Q: Does the session key include LAPI TLS client certificate (keyless TLS bouncer) in addition to `lapiKey`?
  Decision: assumed — yes. That cert is how LAPI selects the bouncer row when the key is empty.
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
