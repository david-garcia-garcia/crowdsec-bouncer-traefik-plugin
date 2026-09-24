# Reclaim context lease

## Language

**Reclaim table**:
A process table that stores one value per key while any bound constructor context is live, plus a short grace after the last holder so Traefik reload can reuse the incarnation.
_Avoid_: `sync.Once`, process singleton, middleware-name key

**Peek**:
A look at one reclaim slot that does not bind a holder, Wake, or stop grace. Returns `(value, Awake|Asleep, ok)`. `ok=false` for missing, gone, or busy; do not wait.
_Avoid_: `PeekLivePrefix`, `View`, a table fork, using Peek to retitle a sleeper

**Holder**:
A strong reference: `Open` increments it and drops it when that constructor ctx is Done. Last holder Sleeps; grace Close disposes.
_Avoid_: Bind reclaim from a bouncing subscriber

**Watcher**:
A weak reference: `Watch` copies the public alias into an `atomic.Value` and does not increment holders, Wake, or stop grace.
_Avoid_: `atomic.Pointer[T]`, waiting in `New` until SetAlias

## Overview

`pkg/reclaim` is a thin shim over the vendored utilities table (`Default`, `ProcessGrace` 30s, `Open` / `OpenWithHooks`, `Peek`, alias `SetAlias` / `Watch` / `ClearPublisher`, `ResetForTest`). Call `OpenWithHooks` with a context that ends when the caller no longer wants the value — in `plugin.go` that is a `context.WithCancel` child of Traefik’s `New` ctx. Watchers attach to an opaque public alias (this plugin encodes `alias:<leg>:<name>`), not the ownership key. `SetAlias` takes a caller-owned group so rename and Clear stay scoped without parsing the alias. Alias APIs are an ad-hoc vendor override until they land upstream. Pass `reclaim.Hooks` as funcs (Yaegi v0.16 panics on asserting a foreign concrete type). Do not take `OpenTyped`. Do not use `*Wrapped` or `OpenWithGrace`. Do not export `PeekLivePrefix` / `View`.

## How to use

- `reclaim.OpenWithHooks(ctx, key, logger, create)` on the process table. Last holder `Sleep()`s; Open during grace `Wake()`s.
- Exact `Peek(key)` before Open when the caller must fail a foreign owner without binding. `ok=false` means miss, gone, or busy — then Open. Do not wait on busy.
- LAPI Client, AppSec Client, and Captcha Client create return the concrete client plus Hooks. Captcha Sleep/Wake MAY be no-ops (no ticker). Tests that need the same incarnation use pointer equality on the `Open` return.
- Process table grace is 30s (`ProcessGrace`) unless the first `New` called `EnsureProcessGrace` with `reclaimGraceSeconds`. Tests that need zero/short grace call `ResetForTestWith`.
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
- There is no Release and no unbind. The only way to give a holder back is to end the context that bound it, which is why callers that can fail after an `Open` bind a cancellable child of their own (`core_plugin_middleware.md` bind context).
- `DefaultGrace` (10s) is the utilities negative-grace fallback. This plugin’s process table uses `ProcessGrace` (30s).
- Yaegi v0.16 panics on asserting a foreign concrete type to closer/sleeper. Pass Hooks funcs. Alias fan-out uses `atomic.Value`, not `atomic.Pointer[T]`.
- Watcher bindings store `*Box` only. After the first `Store`, publish a new `*Box` on every update — never assign `boxed.Value` in place (races with `Unbox`).
- Sleep does not clear aliases. Close / unmap of that incarnation does.
- Callers in another package import this shim, not `github.com/david-garcia-garcia/traefik-middleware-utilities/reclaim`.
- Upstream table uses `time.AfterFunc` for grace so Yaegi v0.16 `interp._select` does not hang.
