# Proposal

## Why
Operators need per-router bounce policy without copying LAPI/AppSec YAML onto every router. Sharing today is an implicit identity hash, so every bouncing middleware still carries the full client blob. Traefik has no plugin-global config; named instances plus an optional holder router are the way to split Open from bounce while still allowing one middleware to do both.

## What Changes
- Public keys become `lapi*` / `appsec*` / `bouncer*` (keep `log*` and `httpTimeoutSeconds`). Old keys are rejected.
- `lapiEnabled` (default true) and `appsecEnabled` (default false) choose legs. `lapiMode` is `live|stream|none|alone` only; `appsec` mode is removed.
- Secrets + enabled → Open and publish `lapiInstance` / `appsecInstance` (empty = Traefik name). Enabled + name + no secrets → subscribe. `New` never waits on a missing name.
- `bouncerEnabled` replaces `enabled`. `bouncerHold` Opens clients and `ServeHTTP` returns 503.
- README documents one-middleware setup, subscribe-by-name, and optional dummy routers.

## Capabilities
### New Capabilities
- `core_plugin_middleware_named-instance`: process named slots for LAPI and AppSec clients; Openers publish; bouncing routers Peek on the request.

### Modified Capabilities
- `core_plugin_middleware_config-validation`: new keys, enable/instance rules, no `appsec` mode.
- `core_plugin_middleware_bouncer`: bounce path Peeks named clients; `bouncerHold` 503; no stored `*Client` from construct.
- `core_plugin_lapi_reclaim-key`: DecisionStore `createdBy` is the LAPI instance name.
- `core_plugin_lapi_scope-union`: only the opener registers `lapiScopeHeaders`.
- `core_plugin_lapi_failure-action`: missing named LAPI client uses the per-router LAPI failure action.
- `core_plugin_appsec_failure-action`: missing named AppSec client uses the per-router AppSec failure action.
- `core_plugin_appsec_client`: Open when this middleware has AppSec secrets; key `appsecEnabled`.

## Impact
- Breaking YAML for every deployment (beta).
- `plugin.go`, `pkg/configuration`, `pkg/bouncer`, `pkg/lapi`, `pkg/appsec`, new `pkg/instance`, tests, e2e, examples, README.
- Identity reclaim (stream ticker, SessionHex) stays. Named slots are aliases.

## What is out
- Decision remapping.
- Old-key aliases.
- Traefik core changes.
