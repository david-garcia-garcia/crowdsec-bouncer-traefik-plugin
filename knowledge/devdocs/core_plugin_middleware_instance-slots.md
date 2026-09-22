# Instance slot tables

## Language

**Slot**:
One named LAPI or AppSec publish target keyed by leg plus instance name. LAPI and AppSec are separate tables, so both may use the string `shared`. Not the Client reclaim key.
_Avoid_: ownership key, SessionHex, DecisionStore, Traefik middleware name as the only key

**Publish**:
Store a client pointer as `current` for that slot, record the publishing middleware, and `Store` the same pointer into every subscriber `atomic.Value` before unlocking. Yaegi-safe: `atomic.Value`, not `atomic.Pointer[T]` and not callbacks.
_Avoid_: channel fan-out, waiting in `New`, request-path Peek

**Subscribe**:
Append a bouncer's `*atomic.Value` to the slot, copy `current` (typed nil when empty), return immediately. Unsubscribe on the bouncer constructor context Done does not Close the backend.
_Avoid_: Bind reclaim from the subscriber, blocking until a publisher exists

**Clear**:
Generation-aware empty of slots still pointing at a dying Client. The dying pointer is the generation. A drifted Traefik name does not leave subscribers bound.
_Avoid_: `Clear(name)` that always stores typed nil, publisher-string match as the generation

**ClearPublisher**:
Drop every slot this middleware still holds on one leg when this constructor no longer Opens that leg.
_Avoid_: Unpublish on Sleep, AfterFunc Unpublish on every constructor ctx cancel

## Overview

Process-wide named slots sit between owner `Open` and bouncer bounce. Spec: `core_plugin_middleware_instance-slots`. Ownership Open keys live on `core_plugin_lapi_reclaim-key` and AppSec session. Constructor wiring: `core_plugin_middleware.md`.

## How to use

- Named slots are aliases on the reclaim table (`alias:<leg>:<name>`), not a second package. `plugin.go` Opens owned legs, then `SetAlias`, then `bouncer.New` with subscribe flags, then `Watch`.
- Typed nil empty: first `Store` fixes the type. Never `Store(nil)`.
- Reject a second publisher on the same alias. Roll back aliases this `New` already wrote, then cancel the holder child.
- Close / unmap of a dying incarnation clears aliases still pointing at it. Sleep does not.
- If this `New` did not Open a leg, `ClearPublisher` that alias prefix for this middleware name.
- Same publisher, new instance name: `SetAlias` clears the previous alias in that leg family.

## Pattern snippet

```go
err := reclaim.SetAlias(ownershipKey, "alias:lapi:"+instanceName, traefikName, (*lapi.Client)(nil))
if !openedLAPI {
	reclaim.ClearPublisher(traefikName, "alias:lapi:")
}
reclaim.Watch("alias:lapi:"+instanceName, reclaim.Watcher{Value: route.LAPIBinding()}, (*lapi.Client)(nil))
```

## Key files

- `vendor/github.com/david-garcia-garcia/traefik-middleware-utilities/reclaim/alias.go`
- `pkg/reclaim/default.go`
- `plugin.go`
- `pkg/bouncer/bouncer.go`

## Gotchas

- Do not wait in Traefik `New` for a publisher.
- `atomic.Value.Store(untyped nil)` panics. Publish and Clear use the same pointer type.
- Dropping the slot mutex before subscriber `Store` lets Clear write nil over a replacement.
