## Why

Four defects and one doc gap around the plugin constructor, all reproduced on `master` `87d1084`.

`New` binds Traefik's long-lived context into every reclaim `Open` it makes. The utilities table drops a
holder only when the bound context is Done, so when a later constructor step fails, the LAPI client an
earlier step already opened is never released — its stream ticker keeps polling LAPI for the process
lifetime while Traefik reports a middleware that failed to build.

`crowdsecMode: appsec` with `crowdsecAppsecEnabled: false` passes `ValidateParams`, opens no decision source
and no AppSec client, and serves every request straight to origin. The operator gets no signal at all.

In appsec mode `bouncer.New` returns before the captcha client is initialised, so
`crowdsecAppsecFailureAction: captcha` bans instead of challenging — `core_plugin_appsec_failure-action`
already says `captcha` SHALL use the configured captcha client.

And `New` mutates Traefik's own `*Config`: after it returns, the caller's struct carries an upper-cased
`LogLevel` and the resolved LAPI secret.

Rebuilt from open PRs #31 and #33 plus three lines salvaged from the closed #22, implemented against current
`master` rather than on their stale bases.

## What Changes

- Derive `bindCtx` from the constructor context inside `New` and cancel it on every error return, so a failed
  constructor releases the decision store, LAPI client, and AppSec client it already opened. Success path does
  not cancel. Named-`err` `defer`, not a closure-captured bool.
- `ValidateParams` logs a loud warning when `crowdsecMode` is `appsec` and `crowdsecAppsecEnabled` is false,
  and still returns nil. It does **not** reject, and does **not** imply AppSec on.
- README states that `crowdsecMode` and `crowdsecAppsecEnabled` are independent axes, that `appsec` plus
  `crowdsecAppsecEnabled: false` enforces nothing, and that the plugin warns about it at startup.
- `bouncer.New` initialises the captcha client in appsec mode when the effective AppSec failure action is
  `captcha`, and conditions the appsec-mode early return on that.
- `New` snapshots `*config` into a local and passes `&prepared` to `lapi.Prepare`, `appsec.Prepare`, the two
  `Open` calls, and `bouncer.New`, with a comment naming the slice and map fields the shallow copy shares.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_bouncer`: `New` releases holders it already opened when it fails, binds a derived
  child of the constructor context, and does not mutate the caller's `*Config`.
- `core_plugin_middleware_config-validation`: the appsec-mode-without-AppSec warning.
- `core_plugin_appsec_failure-action`: `captcha` works in `crowdsecMode: appsec`.

## Impact

- `plugin.go`
- `pkg/bouncer/bouncer.go`
- `pkg/configuration/configuration.go`
- `README.md`
- `zzz_plugin_test.go` (new constructor tests), `pkg/configuration/zzz_configuration_test.go`
- No **BREAKING** public JSON/YAML keys; no new config field
- Out of scope: #33's unreachable error plumbing for `ip.NewChecker` and `GetTemplate` and its 419-line
  `servehttp_test.go`; rejecting or implying the appsec-plus-disabled config; `pkg/decisionscope` keying (#34)
