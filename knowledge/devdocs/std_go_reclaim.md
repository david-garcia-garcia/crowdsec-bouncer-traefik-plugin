# Reclaim context lease

## Language

**Reclaim table**:
A process table that stores one value per key while any bound constructor context is live, plus a short grace after the last holder so Traefik reload can reuse the incarnation.
_Avoid_: `sync.Once`, process singleton, middleware-name key

## Overview

Copy `pkg/reclaim` as-is. Call `reclaim.Open` with Traefik’s `New` ctx. If the value has `Close()`, the table calls it when the incarnation ends.

## How to use

- `reclaim.Open(ctx, key, logger, create)` on the process table.
- `create` runs only for a first put or after dispose.
- Tests: `reclaim.Reset()` / `reclaim.ResetWith(grace)` only.
- Do not rewrite the table; keep it excluded from extra linters this repo enables that geoblock does not.

## Pattern snippet

```go
stored, err := reclaim.Open(ctx, key, log, func() (any, error) {
	return newIncarnation()
})
```

## Key files

- `pkg/reclaim/default.go`
- `pkg/reclaim/table.go`
- `plugin.go`

## Gotchas

- Logger is required.
- Watch `reclaim_put|bind|orphan|reclaim|dispose`.
- Zero grace disposes as soon as the last holder’s ctx is done.
