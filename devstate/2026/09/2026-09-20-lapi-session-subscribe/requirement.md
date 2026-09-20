# Requirement
IssueKey: 2026-09-20-lapi-session-subscribe

## Problem
Two CrowdSec middlewares in one Traefik process can share a LAPI host and API key while disagreeing on Redis (or other session-owned knobs). CrowdSec still stores one GET /v1/decisions/stream cursor and one usage-metrics window on the bouncer row selected by hashed X-Api-Key plus the IP LAPI sees (this process’s outbound address). DestBranch keys the stream Client by SessionHex plus Redis store params, so that disagreement opens a second ticker on the same CrowdSec row.

DestBranch is `master` (origin/HEAD is stale `main` without pkg/lapi reclaim).

## Current (code)
- Stream/alone Open key is `SessionKey` = `lapi:stream:` + `SessionHex` (mode + LAPI scheme/host/path + lapiKey, CAPI machine+password in alone) + hash of Redis store params (`pkg/lapi/session.go` `streamSession` / `SessionKey`). Live/none `Key` is `lapi:` + `SessionHex` + hash of identity including Redis and `MetricsUpdateIntervalSeconds` (`pkg/lapi/identity.go`). Middleware name, outbound IP, and LAPI host alone are not in those keys.
- Different Redis on the same LAPI session opens a second Client and a second DecisionStore (`pkg/lapi/zzz_session_test.go` `TestOpenStream_DifferentRedisIsolatesClientAndStore`). A sleeper with a Redis host change also Opens a new key; the old ticker stays Sleep’d (`TestOpenStream_SleepingRedisHostDoesNotOverlapPollers`).
- Interval / CAPI / `updateMaxFailure` mismatch on a live sibling already shares one Client, silent first-wins (`TestOpenStream_LiveMetricsMismatchSharesSilently`; `OpenStream` comment in `pkg/lapi/session.go`). Header maps union (`pkg/lapi/liveheaderscopes.go`). TLS/timeout last-wins via `AdoptTransport` (`pkg/lapi/client_http.go`); INFO `lapi session joiner adopted` only when transport replaced (`pkg/lapi/session.go`).
- `OpenStream` / `OpenLive` Open DecisionStore on the constructor ctx first, then Client (`pkg/lapi/session.go`). Store reclaim key is `decisionstore:` + `SessionHex` + Redis params (`pkg/lapi/decisionstore.go` `StoreKey`). Those keys stay in lockstep only because both include Redis. `Client.Close` does not Close the store; store Close is the store’s reclaim hook (`pkg/lapi/client.go` `New` comment; `pkg/decisionstore/store.go` `Open`).
- Join vs create is reclaim table state for a given Open key (live bind / Sleep+Wake / empty create) (`vendor/github.com/david-garcia-garcia/traefik-middleware-utilities/reclaim/table.go`). Traefik `New` is per router-handler build, not per middleware name (`knowledge/research/ext_traefik_plugins_yaegi-constructor`). Client does not record a set of live holder middleware names (`not found` as a holder-name set; `clientFromStored` returns the value only). `Peek` / `PeekLivePrefix` are absent.
- Wake already resumes tickers with `startup=false` and keeps the store (`pkg/lapi/client.go` `Wake`; `TestOpenStream_SleepingIntervalChangeWakesSameSlot`). First create logs `crowdsec connection started` (`MsgConnectionStarted`), not that this LAPI key owns the process-wide stream/metrics.
- README already says one stream per LAPI key + bouncer IP and that a second config needs a different key; it also says interval / `updateMaxFailure` / CAPI scenarios are create-time first-wins (`README.md` Note). It does not say Redis/interval disagreements are ignored rather than isolated. LAPI physics: `knowledge/research/ext_crowdsec_lapi_stream-cursor`, `knowledge/research/ext_crowdsec_lapi_usage-metrics`.

## Desired
1. Stream/alone Client reclaim key is the LAPI session (scheme+host+path+lapiKey, and mode). Not Redis, not Traefik middleware name, not outbound IP, not host alone (two keys on one host stay two Clients).
2. Join vs reconfigure is reclaim table state, not middleware name. Live holders → subscribe. Sleep/grace → Wake (`startup=false`, store+cursor kept). Empty → create.
3. Client records live holder middleware names as a set (same idea as `liveHeaderScopes`) so WARN can name who joined whom. Not a single `ownerName`.
4. Subscribe (live sibling): reuse the existing Client and its DecisionStore. Do not fail New. First-wins for session-owned knobs. WARN listing every ignored field and that isolation requires a second bouncer API key. Session-owned at least: redisCacheEnabled/host/password/database/read hosts, updateIntervalSeconds, metricsUpdateIntervalSeconds, updateMaxFailure, CAPI scenarios. Per-router stays on Bouncer (failure actions, templates, trusted IPs, Enabled, captcha). TLS/timeout stay AdoptTransport last-wins. decisionScopeHeaders stay live union.
5. Wake/reconfigure: keep DecisionStore and CrowdSec cursor; do not `startup=true` because YAML changed. AdoptTransport already. Redis YAML change on Wake keeps the live store and WARNs; no migrate memory↔Redis in this ticket.
6. DecisionStore is opened in Client create() (child of the Client incarnation), not a sibling reclaim Open in plugin.go/OpenStream. Store Close stays the Client Close hook. StoreKey/Redis prefix/SessionHex for Redis keys stay reachable (no Redis key migration).
7. Operator surface: WARN on subscribe mismatch (fields + middleware names + second API key). INFO on first create that this LAPI key owns the process-wide stream/metrics. README: one key = one ticker + one metrics window in this instance; Redis/interval disagreements are ignored, not isolated.

## Affected
- `pkg/lapi/session.go` (`SessionKey`, `OpenStream` / `OpenLive` store-then-Client)
- `pkg/lapi/identity.go` (live/none `Key` Redis hash — only if explore takes it)
- `pkg/lapi/client.go` (create store, Close hook, holder-name set, subscribe WARN, first-create INFO)
- `pkg/lapi/decisionstore.go` (`OpenDecisionStore` call site; StoreKey/SessionHex remain)
- `pkg/lapi/zzz_session_test.go` (Redis-isolation and silent-mismatch tests invert)
- `README.md` shared-session Note
- OpenSpec / usage packets for `core_plugin_lapi_reclaim-key` and related middleware language

## Out of scope
- Two Traefik processes (reclaim is process-local; docs only)
- Migrating a live store between Redis hosts (no memory↔Redis migrate)
- Failing New on conflict
- Keying Client by LAPI host alone
- Using one middleware name to detect reload
- Restoring Peek/PeekLivePrefix/warn-and-wire sibling slots

## Unknowns
- Whether stream+live on the same key should share one metrics reporter (explore; do not treat as decided).
- Whether live/none Client `Key` also drops Redis the same way (explore; do not treat as decided).

## Tensions
- README already tells operators that two stream configs on the same key fight over one cursor; DestBranch code still isolates Clients by Redis, so the silent second ticker contradicts both LAPI physics and that Note.
- Existing tests encode Redis isolation as the contract (`TestOpenStream_DifferentRedisIsolatesClientAndStore`, `TestOpenStream_SleepingRedisHostDoesNotOverlapPollers`); this change inverts them to share+WARN.
- Live/none still hashes Redis (and metrics interval) into `Key`. Stream/alone dropping Redis while live keeps it is a possible split; ticket leaves that to explore.
- Store is a sibling reclaim today; dropping Redis from the Client key without moving store Open into Client create() would leak a zombie DecisionStore on join.
