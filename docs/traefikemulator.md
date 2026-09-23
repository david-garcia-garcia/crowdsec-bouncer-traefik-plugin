# traefikemulator

Test helper at `pkg/traefikemulator`. Test suites import it and pass `New`. The package does not import this module.

It copies `RouterFactory.CreateRouters`: cancel the previous generation, then construct every route on one new context. `Serve(routeName, req)` calls that generation's handler. No host, path, or priority matching.

`Apply` constructs in the order the test lists. Traefik ranges a map, so both orders are production. Tests force each order.

A `New` that returns an error is left out of the generation. The generation context stays live for the routes that succeeded. A route omitted from the next `Apply` is not constructed again; it dies with the old context.

`Serve` reaches only the current generation. A handler the test kept from the previous generation is out of scope. Traefik can still be inside that handler on an in-flight request; this helper does not model that.

Grace stays where tests already set it (`reclaim.ResetForTestWith`). `Apply` does not sleep.

## Fixture

These tests use a spy constructor. They do not call the plugin.

- Previous generation's context is already cancelled when the next `New` runs.
- Every route in one generation shares that context. One cancel ends all of them.
- A route omitted from the next `Apply` is not constructed.
- A failed `New` is absent from `Serve`. Its sibling still serves, and the sibling's context is not cancelled.
- `Serve` after `Apply` does not call the previous handler.
- Two routes with the same middleware name get two `New` calls. One generation cancel ends both.

## Plugin

Observable signal: `streamStartupBlock` is 503 when the subscribed client is missing, and the next handler runs when it is bound. Client pointer equality is the grace signal. Use the existing live LAPI stub.

Owner publishes a LAPI instance. Subscriber only watches that name. `Apply` lists both routes.

- **Subscriber before owner, within grace.** Reload twice. After each `Apply`, subscriber `Serve` is bound, and both generations share one client pointer. This is the production race: `cancel` drops Watch on another goroutine, then the new `New` calls run immediately. The subscriber must still be bound when it is constructed first.
- **Owner before subscriber, within grace.** Same outcome. Watch must copy the client already published in this generation.
- **Reload after grace.** Subscriber `Serve` is bound to a new client pointer.
- **Owner removed, subscriber kept.** Sleep does not unpublish, so right after `Apply` the subscriber still serves that client. After grace, `Serve` is 503 and the client is closed.
- **Subscriber removed, owner kept.** The owner's client pointer is unchanged within grace. The owner still serves.
- **Second publisher of the same instance name.** That route's `New` fails and is absent. The first publisher still serves and is still the published client.
- **Owner reloads with the leg disabled.** `ClearPublisher` runs. Subscriber `Serve` is 503. The client sleeps because this generation did not Open it.
- **Two holders, one middleware name.** Both serve. Next generation keeps one. Within grace that holder still has the same client.
- **AppSec subscriber, owner before and after.** Same bound outcome as the LAPI pair. `ReceiveAppSec` is a separate hook.

`TestNew_ReclaimWithinGrace` and `TestNew_DisposeAfterGrace` stay. They cover one holder. They do not cover a subscriber on the same generation.
