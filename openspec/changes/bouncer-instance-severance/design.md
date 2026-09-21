# Design

## Context
Yaegi `New` runs per router, order undefined. Reclaim already shares Clients by LAPI/AppSec identity. Operators cannot name that share, and bouncing `New` always Opens. Confirmed surface: domain-prefixed keys, enable flags, named instances, optional `bouncerHold`, one middleware may still Open both clients and bounce.

## Goals / Non-Goals
- Goals: named publish/subscribe, late bind on the request path, domain-prefixed config, README severance, keep one-object setup.
- Non-Goals: YAML aliases, decision remap, replacing identity reclaim, blocking `New`.

## Decisions
1. **Named slot beside reclaim.** After identity `Open`, Publish `lapi-instance:<name>` / `appsec-instance:<name>` holding the `*Client` in `atomic.Value`. Bounce `ServeHTTP` Peeks. Subscribers do not bind reclaim (holder teardown stops the stream after grace).
2. **Open vs subscribe.** `hasLapiSecrets` = key, client cert, or alone CAPI. `lapiEnabled` + secrets → Open + Publish. `lapiEnabled` + `lapiInstance` + no secrets → subscribe. `lapiEnabled` + neither → `ValidateParams` error. Disabled + leftover secrets or instance → error. Same for AppSec (`appsecEnabled` + key).
3. **Instance name.** Empty `lapiInstance` on Open is the Traefik middleware `name`. DecisionStore `createdBy` is that instance name. Two Openers of the same instance share. A different instance name on the same SessionHex fails `New`.
4. **`lapiMode`.** Read only on Open. Values `live|stream|none|alone`. `appsec` removed. AppSec-only: `lapiEnabled: false`.
5. **Hold.** `bouncerHold` Opens then returns a handler that writes 503 and does not call `next`. `bouncerHold` + `bouncerEnabled` is a validation error.
6. **Missing slot.** Peek miss uses `bouncerLapiFailureAction` / `bouncerAppsecFailureAction`.
7. **Scopes.** Opener registers `lapiScopeHeaders` at Open. Subscribers do not.
8. **Keys.** Rename all public JSON tags to the domain tables in explore. `GetVariable` follows new struct field names (`LapiKey` + `LapiKeyFile`).

## Risks
- Traefik constructor deadlock if anyone waits in `New` — do not wait.
- Stale `*Client` captured at first Peek — Peek every request.
- Two Openers same name different LAPI host — fail the second `New`.
