# LAPI opener stream scopes

## Language

**Opener stream scopes**:
The extra CrowdSec scope names the LAPI stream poll follows (`crowdsecLapiStreamScopes`). `ip` and `range` are always on the poll. Omitted or empty is `ip,range` only. Not copied from `decisionScopeHeaders`.
_Avoid_: live-router scope union, `registerLiveHeaderScopes`, PeekLivePrefix

## Overview

How a stream `lapi.Client` builds `scopes=` from the opener list. Spec: `core_plugin_lapi_scope-union`. Canonical list is part of SessionHex in stream mode (`core_plugin_lapi_reclaim-key.md`). Header extraction stays on the bouncer.

## How to use

- Pass `cfg.CrowdsecLapiStreamScopes` into `CanonicalStreamScopes` at Open. Do not union bouncer header maps into the poll.
- CAPI (alone) still omits `scopes=`. Live/none still pass scopes per `LiveLookup`.
- When a bouncing middleware binds, warn once if `decisionScopeHeaders` keys are not covered by the opener list. Warn again when Publish swaps the client.
- Do not use `atomic.Pointer[T]`, `sync.Once`, or a package global union table.

## Pattern snippet

```go
query := client.streamQuery()
missing := decisionscope.MissingStreamScopes(client.StreamScopes(), cfg.DecisionScopeHeaders)
```

## Key files

- `pkg/decisionscope/lookup.go`
- `pkg/lapi/session.go`
- `pkg/lapi/client_decisions.go`
- `pkg/instance/tables.go` (bind-time coverage WARN)

## Gotchas

- A list change is a new SessionHex and a new store (`startup=true` refill). YAML order does not matter.
- Empty opener list does not copy Country from `decisionScopeHeaders`.
- Growing the list does not send `startup=true` on an existing store; change the list to fork the store.
