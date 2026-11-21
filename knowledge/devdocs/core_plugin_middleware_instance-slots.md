# Instance slot tables

## Language

**Slot**:
One named LAPI, AppSec, captcha, ModSec, or rate-limit publish target keyed by group plus instance name. The five groups are separate, so all may use the string `shared`. Not the Client reclaim key.
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

**Published leg**:
One `publishedLeg` entry in `plugin.go` `publishedLegs()`: the plain funcs `New` walks to prepare, open, claim, subscribe, and Watch that leg. Not generic.
_Avoid_: a `switch group` arm per leg, a hand-written rollback list

**Leg binding**:
A route's side of one published leg: `legBinding` on `Bouncer` (subscribed flag, instance name, the `*reclaim.Box` Watch stored, the incarnation last traced).
_Avoid_: per-leg `<leg>Bound` / `<leg>Received` fields

## Overview

Process-wide named slots sit between owner `Open` and bouncer bounce. Spec: `core_plugin_middleware_instance-slots`. Ownership Open keys live on `core_plugin_lapi_reclaim-key`, AppSec session, captcha `OwnershipKey` (middleware name plus instance-owned knobs including the recaptcha-enterprise knobs and `logLevel`, `logFilePath`, `logFormat`; `pkg/captcha/session.go`), ModSec `OwnershipKey` (middleware name plus sidecar knobs; `pkg/modsecurity/session.go`), and rate-limit `OwnershipKey` (middleware name plus Redis settings, bucket rows, and policy; `pkg/ratelimit/client.go`). Constructor wiring: `core_plugin_middleware.md`.

## How to use

- Named slots are opaque aliases on the reclaim table. This plugin encodes them as `alias:<leg>:<name>` in `instanceAlias`; the table never parses that string. `plugin.go` walks the `publishedLegs()` table: `prepare` each leg, `open` each enabled leg (`ClearPublisher` the others), `SetAlias` each enabled leg with group `lapi`/`appsec`/`captcha`/`modsec`/`ratelimit`, then `bouncer.New` with one `bouncer.Subscriptions` value, then `Watch` each subscribed leg. `Watch` drops that subscriber when its ctx is done.
- Add a published leg in three places, nothing else: one `publishedLeg` entry in `publishedLegs()` (`plugin.go`: group, enabled, instanceName, prepare, open, ownershipKey, subscribe, typed-nil empty, receive); one `legBinding` field on `Bouncer` plus a `Subscriptions` field, both set in `bouncer.New`; and a typed `loaded<Leg>()` plus exported `Receive<Leg>(published any)` that calls `receiveBinding` (`pkg/bouncer/bouncer_leg_<leg>.go`). Per-leg bind work (LAPI's stream-scope warning) is the `onBind` hook, not a copy of the trace.
- Table order is open order, claim order, and rollback order: a failed claim clears every earlier enabled entry and nothing after it.
- Hash captcha `OwnershipKey` from middleware name plus instance-owned captcha knobs including `logLevel`, `logFilePath`, and `logFormat`. Slot name, bounce, failure actions, and the remediation header stay off it.
- Watchers `Store` a `reclaim.Box` only. The inner value is the client or typed nil. Never `Store(nil)` and never change the `atomic.Value` type (Yaegi panics). On each publish, `Store` a **new** `*Box`; do not assign `Box.Value` in place while ServeHTTP may `Unbox` the same pointer.
- Reject a second publisher on the same alias. Roll back with `ClearPublisher(name, group)`, then cancel the holder child.
- Close / unmap of a dying incarnation clears aliases still pointing at it (reverse index on the slot). Sleep does not.
- If this `New` did not Open a leg, `ClearPublisher(name, group)` for that middleware.
- Same publisher, new instance name in the same group: `SetAlias` clears the previous alias in that group.

## Pattern snippet

```go
// plugin.go: one table entry per published leg.
{
	group:        legModsec,
	enabled:      func(config *configuration.Config) bool { return config.ModsecEnabled },
	instanceName: func(config *configuration.Config) string { return config.ModsecInstanceName },
	prepare:      modsecurity.Prepare,
	open: func(bindCtx context.Context, config *configuration.Config, log *slog.Logger, traefikName string) error {
		_, err := modsecurity.Open(bindCtx, config, log, traefikName, pluginVersion)
		return err
	},
	ownershipKey: modsecurity.OwnershipKey,
	subscribe:    func(subscriptions *bouncer.Subscriptions) { subscriptions.ModSec = true },
	empty:        (*modsecurity.Client)(nil),
	receive:      func(route *bouncer.Bouncer) func(any) { return route.ReceiveModSec },
},

// pkg/bouncer/bouncer_leg_modsec.go: typed load and receive over the shared binding.
func (b *Bouncer) loadedModSec() *modsecurity.Client {
	client, _ := reclaim.Unbox(&b.modsecLeg.bound).(*modsecurity.Client)
	return client
}

func (b *Bouncer) ReceiveModSec(published any) {
	b.receiveBinding(&b.modsecLeg, published, func() string { return b.loadedModSec().Incarnation() }, nil)
}
```

## Key files

- `vendor/github.com/david-garcia-garcia/traefik-middleware-utilities/reclaim/alias.go`
- `pkg/reclaim/default.go`
- `plugin.go`
- `pkg/captcha/session.go`
- `pkg/modsecurity/session.go`
- `pkg/bouncer/bouncer.go`
- `pkg/bouncer/bouncer_leg_modsec.go`
- `pkg/bouncer/leg_binding.go` (`legBinding`, `receiveBinding`, `traceBinding`)
- `pkg/bouncer/bouncer_leg_utils.go` (`storeBinding`)
- `zzz_leg_lifecycle_test.go` (bound / unbound traces and claim rollback per leg)
- `pkg/bouncer/zzz_yaegi_leg_binding_test.go` (bindings under Yaegi)

## Gotchas

- Do not wait in Traefik `New` for a publisher.
- A `logLevel`, `logFilePath`, or `logFormat`-only rebuild forks captcha `OwnershipKey`. Create stores the constructor logger. Do not rewrite `Client.log` on reclaim.
- `atomic.Value.Store(untyped nil)` panics. Publish and Clear use the same pointer type.
- Do not mutate `Box.Value` after that Box is already in an `atomic.Value`. Concurrent `Unbox` reads the field without sync; a torn `any` can panic or show a stale/nil client. Publish with `dest.Store(&reclaim.Box{Value: value})` every time.
- Dropping the slot mutex before subscriber `Store` lets Clear write nil over a replacement.
- No generics in the leg table or the binding: Yaegi v0.16.1 panics on a generic type named through a package qualifier (`legBinding[T]` used from `plugin.go`).
- No interface- or `any`-typed "last received Client" field on the binding: Yaegi v0.16.1 fails at runtime on it although Go passes. `legBinding` keeps the last traced incarnation as a `string`, so a Client whose `Incarnation()` is empty traces as nil; every real Client sets it in its constructor, and test Clients must too (`lapi.NewTestClient`).
- Subscribing before any publish: under Yaegi, `Watch` delivers the typed nil and the route traces one `crowdsec bouncer unbound` without incarnation; compiled Go treats typed nil as the initial nil and traces nothing. Replace A by B traces unbound A, then bound B.
- Yaegi v0.16.1 keeps the previous loop iteration's value when a comma-ok type assertion fails; test programs that parse logs in a loop read fields with `fmt.Sprint` and nil checks.
