# Reclaim context lease

## Language

**Reclaim table**:
A process table that stores one value per key while any bound constructor context is live, plus a short grace after the last holder so Traefik reload can reuse the incarnation.
_Avoid_: `sync.Once`, process singleton, middleware-name key

## Overview

Copy `pkg/reclaim` as-is. Call `reclaim.Open` with Traefik’s `New` ctx. Same-package values may implement `Sleep`/`Wake`/`Close`. A value defined in another package MUST be returned as `*reclaim.Wrapped` (funcs, not a type assert): Yaegi v0.16 panics on asserting a foreign concrete type to those interfaces. CrowdsecConnection puts use `OpenWithGrace(..., ReclaimGraceDuration, ...)` (30s). Do not change table `DefaultGrace` (10s) to special-case one type.

## How to use

- `reclaim.Open(ctx, key, logger, create)` on the process table. Last holder `Sleep()`s if the value has it; Open during grace `Wake()`s.
- CrowdsecConnection `create` returns `*reclaim.Wrapped` (`Sleep`/`Wake`/`Close` as funcs). Peek still returns `*CrowdsecConnection`.
- CrowdsecConnection puts use `OpenWithGrace(..., ReclaimGraceDuration, ...)` (30s). Do not change table `DefaultGrace` (10s) to special-case one type.
- `create` runs only for a first put or after grace Close.
- Tests: `reclaim.ResetForTest()` / `reclaim.ResetForTestWith(grace)` only.
- `Peek(key)` inspects holders/sleep without binding (`View`). `PeekLivePrefix(prefix)` returns one live slot under that stem. Callers do not Close slots.
- Do not rewrite the table; keep it excluded from extra linters this repo enables that geoblock does not.

## Pattern snippet

```go
stored, err := reclaim.OpenWithGrace(ctx, key, log, 30*time.Second, func() (any, error) {
	conn, err := newConnection()
	if err != nil {
		return nil, err
	}
	return &reclaim.Wrapped{Value: conn, Sleep: conn.Sleep, Wake: conn.Wake, Close: conn.Close}, nil
})
```

## Key files

- `pkg/reclaim/default.go`
- `pkg/reclaim/table.go`
- `plugin.go`

## Gotchas

- Logger is required.
- Watch `reclaim_put|bind|orphan|reclaim|dispose`.
- Zero table grace disposes as soon as the last holder’s ctx is done.
- `DefaultGrace` is 10s when `Open` is used without `OpenWithGrace`. Do not change that table-wide default to special-case one stored type; pass the slot wait at put.
- Yaegi v0.16 panics on asserting a foreign concrete type to `closer`/`sleeper`. Do not add that assert back.
- Yaegi v0.16 corrupts a 4-value Peek return (`any`, `int`, `bool`, `bool`). Keep `View`.
