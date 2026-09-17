# LAPI connection

## Language

**transport**:
LAPI HTTP plus the request header name and the CAPI/LAPI key. Stored on Client as `atomic.Value`.
_Avoid_: `atomic.Pointer[T]`, a write-once Client `httpClient` field, CrowdsecConnection

## Overview

`package lapi` keeps construct/close in `client.go` and LAPI/CAPI HTTP in `client_http.go`. HTTP+auth lives as unexported `transport`. After `OpenStream` / `OpenLive` bind, `AdoptTransport` last-wins TLS/timeout on the same Client. Specs: `core_plugin_lapi_connection` (concurrent `AdoptTransport` last-write), `core_plugin_lapi_reclaim-key` (Open key).

## How to use

- Declare `transport` in `client_http.go`. Store it on Client as `atomic.Value`. Do not use `atomic.Pointer[T]` (Yaegi v0.16).
- After `OpenStream` / `OpenLive` bind, call `AdoptTransport(cfg)`: Store the new transport and idle-close the previous `*http.Client`. Last `New` wins.
- Write the CAPI token on the stored transport (`getToken`). Do not keep a write-once Client key field beside it.
- Pass `defaultDecisionSeconds` into `LiveLookup`. Do not store that TTL on Client.
- Keep `StreamStartupBlock` write-once at `startStream`. First incarnation keeps it. Do not put it on Bouncer. Do not mutate it after construct.
- `logInfo` includes reclaim `sessionKey` (stream/alone `SessionKey`, live/none `Key`) and `reason` (`started|sleeping|waking|closed`). Name transport replace and a live joiner `ignored` vs `adopted` at INFO.

## Pattern snippet

```go
client.sessionKey = bindKey
replaced, err := client.AdoptTransport(cfg)
value, err := client.LiveLookup(remoteIP, scopes, defaultDecisionSeconds)
```

## Key files

- `pkg/lapi/client_http.go`
- `pkg/lapi/client.go`
- `pkg/lapi/client_live.go`
- `pkg/lapi/session.go`

## Gotchas

- Concurrent `AdoptTransport` last-writes the stored transport and idle-closes the value it replaced. No extra mutex around write-once Client scalars.
- Remaining hash fields (intervals, Redis host/auth/db, `updateMaxFailure`, CAPI scenarios, `decisionScopeHeaders`) still first-wins via `PeekLivePrefix`.
- `reclaim_put`, `reclaim_reclaim`, and `reclaim_dispose` stay DEBUG.
