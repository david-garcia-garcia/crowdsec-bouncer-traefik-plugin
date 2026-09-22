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

## Overview

Process-wide named slots sit between owner `Open` and bouncer bounce. Spec: `core_plugin_middleware_instance-slots`. Ownership Open keys live on `core_plugin_lapi_reclaim-key` and AppSec session. Constructor wiring: `core_plugin_middleware.md`.

## How to use

- Put both tables in `pkg/instance`. `plugin.go` Opens owned legs, then `PublishAll`, then `bouncer.New` with subscribe flags, then `Subscribe`.
- Typed nil empty: first `Store` fixes the type. Never `Store(nil)`.
- Reject a second publisher in the same table. Roll back every slot this `New` already wrote before unlocking, then cancel the holder child.
- Clear on grace `Close` only when `current` is still the dying pointer and the recorded publisher matches.
- On Wake rename, unpublish the Client's last published name before publishing the new one.

## Pattern snippet

```go
err := instance.PublishAll(attempts)
instance.Subscribe(instance.LegLAPI, name, instance.Subscriber{
	Value: route.LAPIBinding(), TraefikName: traefikName, Log: log,
})
```

## Key files

- `pkg/instance/tables.go`
- `plugin.go`
- `pkg/bouncer/bouncer.go`

## Gotchas

- Do not wait in Traefik `New` for a publisher.
- `atomic.Value.Store(untyped nil)` panics. Publish and Clear use the same pointer type.
- Dropping the slot mutex before subscriber `Store` lets Clear write nil over a replacement.
