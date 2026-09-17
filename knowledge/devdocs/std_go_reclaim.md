# Reclaim context lease

## Language

**Reclaim table**:
A process table that stores one value per key while any bound constructor context is live, plus a short grace after the last holder so Traefik reload can reuse the incarnation.
_Avoid_: `sync.Once`, process singleton, middleware-name key

## Overview

`pkg/reclaim` is a source-sync of traefik-middleware-utilities `reclaim/` plus Peek helpers. Call `reclaim.Open` / `OpenWithHooks` with Traefik’s `New` ctx. Pass `reclaim.Hooks` as funcs (Yaegi v0.16 panics on asserting a foreign concrete type). The process table wait is `ProcessGrace` (30s). Do not use `*Wrapped` or `OpenWithGrace`.

## How to use

- `reclaim.OpenWithHooks(ctx, key, logger, create)` on the process table. Last holder `Sleep()`s; Open during grace `Wake()`s.
- LAPI Client and AppSec Client create return the concrete client plus Hooks. Peek still returns the concrete `*lapi.Client` or `*appsec.Client`.
- Process table grace is 30s (`ProcessGrace`). Tests that need zero/short grace call `ResetForTestWith`.
- `create` runs only for a first put or after grace Close.
- Tests: `reclaim.ResetForTest()` / `reclaim.ResetForTestWith(grace)` only.
- `Peek(key)` inspects holders/sleep without binding (`View`). `PeekLivePrefix(prefix)` returns one live slot under that stem. Callers do not Close slots.

## Pattern snippet

```go
stored, err := reclaim.OpenWithHooks(ctx, key, log, func() (any, reclaim.Hooks, error) {
	client, err := newClient()
	if err != nil {
		return nil, reclaim.Hooks{}, err
	}
	return client, reclaim.Hooks{Sleep: client.Sleep, Wake: client.Wake, Close: client.Close}, nil
})
```

## Key files

- `pkg/reclaim/table.go`
- `pkg/reclaim/default.go`
- `pkg/reclaim/peek.go`
- `plugin.go`

## Gotchas

- Logger is required.
- Watch `reclaim_put|bind|orphan|reclaim|dispose`.
- Zero table grace disposes as soon as the last holder’s ctx is done.
- `DefaultGrace` (10s) is the utilities negative-grace fallback. This plugin’s process table uses `ProcessGrace` (30s).
- Yaegi v0.16 panics on asserting a foreign concrete type to closer/sleeper. Pass Hooks funcs.
- Yaegi v0.16 corrupts a 4-value Peek return (`any`, `int`, `bool`, `bool`). Keep `View`.
- Do not import `github.com/david-garcia-garcia/traefik-middleware-utilities/reclaim` (Peek would be unreachable).
