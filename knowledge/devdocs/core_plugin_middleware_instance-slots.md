# Instance slot tables

## Language

**Slot**:
One named LAPI, AppSec, or captcha publish target keyed by group plus instance name. The three groups are separate, so all may use the string `shared`. Not the Client reclaim key.
_Avoid_: ownership key, SessionHex, DecisionStore, Traefik middleware name as the only key, a second slot table

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

Process-wide named slots sit between owner `Open` and bouncer bounce. Spec: `core_plugin_middleware_instance-slots`. Ownership Open keys live on `core_plugin_lapi_reclaim-key`, AppSec session, and captcha `OwnershipKey` (middleware name plus instance-owned knobs; `pkg/captcha/session.go`). Constructor wiring: `core_plugin_middleware.md`.

## How to use

- Named slots are opaque aliases on the reclaim table. This plugin encodes them as `alias:<leg>:<name>` in `instanceAlias`; the table never parses that string. `plugin.go` Opens owned legs, then `SetAlias` with group `lapi`/`appsec`/`captcha`, then `bouncer.New` with subscribe flags, then `Watch`. `Watch` drops that subscriber when its ctx is done.
- Watchers `Store` a `reclaim.Box` only. The inner value is the client or typed nil. Never `Store(nil)` and never change the `atomic.Value` type (Yaegi panics).
- Reject a second publisher on the same alias. Roll back with `ClearPublisher(name, group)`, then cancel the holder child.
- Close / unmap of a dying incarnation clears aliases still pointing at it (reverse index on the slot). Sleep does not.
- If this `New` did not Open a leg, `ClearPublisher(name, group)` for that middleware.
- Same publisher, new instance name in the same group: `SetAlias` clears the previous alias in that group.

## Pattern snippet

```go
err := reclaim.SetAlias(ownershipKey, instanceAlias("lapi", instanceName), traefikName, "lapi")
if !openedLAPI {
	reclaim.ClearPublisher(traefikName, "lapi")
}
reclaim.Watch(ctx, instanceAlias("lapi", instanceName), (*lapi.Client)(nil), route.ReceiveLAPI)
reclaim.Watch(ctx, instanceAlias("captcha", captchaName), (*captcha.Client)(nil), route.ReceiveCaptcha)
```

## Key files

- `vendor/github.com/david-garcia-garcia/traefik-middleware-utilities/reclaim/alias.go`
- `pkg/reclaim/default.go`
- `plugin.go`
- `pkg/captcha/session.go`
- `pkg/bouncer/bouncer.go`

## Gotchas

- Do not wait in Traefik `New` for a publisher.
- `atomic.Value.Store(untyped nil)` panics. Publish and Clear use the same pointer type.
- Dropping the slot mutex before subscriber `Store` lets Clear write nil over a replacement.
