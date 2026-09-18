# Reclaim context lease

## Language

**Reclaim table**:
A process table that stores one value per key while any bound constructor context is live, plus a short grace after the last holder so Traefik reload can reuse the incarnation.
_Avoid_: `sync.Once`, process singleton, middleware-name key

## Overview

`pkg/reclaim` is a thin shim over traefik-middleware-utilities `reclaim` (`Default`, `ProcessGrace` 30s, `Open` / `OpenWithHooks`, `ResetForTest` / `ResetForTestWith`). Call `reclaim.Open` / `OpenWithHooks` with Traefik’s `New` ctx. Pass `reclaim.Hooks` as funcs (Yaegi v0.16 panics on asserting a foreign concrete type). Do not take `OpenTyped` (it still takes `func() (any, Hooks, error)`). Do not use `*Wrapped` or `OpenWithGrace`. Do not export or call `Peek` / `PeekLivePrefix` / `View`.

## How to use

- `reclaim.OpenWithHooks(ctx, key, logger, create)` on the process table. Last holder `Sleep()`s; Open during grace `Wake()`s.
- LAPI Client and AppSec Client create return the concrete client plus Hooks. Tests that need the same incarnation use pointer equality on the `Open` return.
- Process table grace is 30s (`ProcessGrace`). Tests that need zero/short grace call `ResetForTestWith`.
- `create` runs only for a first put or after grace Close.
- Tests: `reclaim.ResetForTest()` / `reclaim.ResetForTestWith(grace)` only.

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

- `pkg/reclaim/default.go`
- `plugin.go`

## Gotchas

- Logger is required.
- Watch `reclaim_put|bind|orphan|reclaim|dispose`.
- Zero table grace disposes as soon as the last holder’s ctx is done.
- `DefaultGrace` (10s) is the utilities negative-grace fallback. This plugin’s process table uses `ProcessGrace` (30s).
- Yaegi v0.16 panics on asserting a foreign concrete type to closer/sleeper. Pass Hooks funcs.
- Callers in another package import this shim, not `github.com/david-garcia-garcia/traefik-middleware-utilities/reclaim`.
- Upstream table uses `time.AfterFunc` for grace so Yaegi v0.16 `interp._select` does not hang.
