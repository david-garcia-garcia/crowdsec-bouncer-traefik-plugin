# LAPI reclaim key

## Language

**Ownership key**:
The Open key for one `lapi.Client`: middleware name plus that client's knobs (mode, scheme, host, path, key, TLS, effective HTTP timeout, Redis, `crowdsecLapiStreamScopes`, CAPI credentials, `updateIntervalSeconds`, `metricsUpdateIntervalSeconds`, `updateMaxFailure`, `crowdsecCapiScenarios`, `defaultDecisionSeconds`). Prefix `lapi:owner:`. Same middleware name and same knobs Wake. A different middleware name is a different Client.
_Avoid_: slot name as the Client key, IdentityHex as the Open suffix, Bouncer, CrowdsecConnection, AppSec host

**SessionHex**:
The DecisionStore identity hash: mode, LAPI URL+key, CAPI machine/password, `defaultDecisionSeconds`, stream canonical scope list, and the Redis set only when `redisCacheEnabled` is true. Not middleware name. Not the slot name.
_Avoid_: leftover Redis fields when Redis is off, `decisionScopeHeaders`, `streamStartupBlock`

## Overview

How this plugin keys a reclaimed `lapi.Client` versus the store it writes. Spec: `core_plugin_lapi_reclaim-key`. Constructor `ctx` is the reclaim holder. Stream `scopes=` is owned by `core_plugin_lapi_scope-union`. Slots: `core_plugin_middleware_instance-slots.md`.

## How to use

- Call `lapi.OwnershipKey(cfg, middlewareName)` from `OpenStream` / `OpenLive`.
- `StoreKey` is `decisionstore:` plus `SessionHex` only.
- A knob on the ownership key that is not in SessionHex (interval, metrics, `updateMaxFailure`, CAPI scenarios) Opens a new Client and keeps the store.
- `defaultDecisionSeconds` is on both: new Client and new store.
- Redis off: leftover host/password/database/read hosts do not change SessionHex. Redis on: the whole set is in SessionHex (read hosts sorted).
- Leave `streamStartupBlock` out of both keys.
- Pass `reclaim.Hooks` for Sleep/Wake/Close. An unreclaimed `lapi.Client` waits `ProcessGrace` 30s.

## Pattern snippet

```go
bindKey := lapi.OwnershipKey(cfg, middlewareName)
lapiClient, err := lapi.OpenStream(ctx, cfg, log, middlewareName, pluginVersion)
```

## Key files

- `pkg/lapi/session.go`
- `pkg/lapi/identity.go`
- `pkg/lapi/client.go`
- `pkg/lapi/decisionstore.go` (`StoreKey` / `OpenDecisionStore`)
- `pkg/decisionstore/store.go`

## Gotchas

- Two stream owners with the same host and API key both succeed; log `crowdsec lapi stream collision`. Do not fail `New` with Peek exclusive-name.
- Timeout and TLS live on the ownership key. A change is a new Client, not Adopt-only.
- DecisionStore reclaim key is `decisionstore:` + `SessionHex` only (`core_plugin_decisionstore.md`).
- Isolated CrowdSec backends need a second bouncer key (or a different LAPI host) when both Open. Subscribers share by not sending a key.
