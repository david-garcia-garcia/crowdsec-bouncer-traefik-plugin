## Purpose

Traefik Yaegi loads `CreateConfig` and `New` from the module-root package. `New` binds its reclaim holders to a context derived from the constructor context, works on a snapshot of the config Traefik owns, and returns a per-router Bouncer that holds request policy and MUST NOT start a process-wide stream ticker.

## Requirements

### Requirement: Yaegi constructors stay on the module-root package
The plugin SHALL export `CreateConfig` and `New` from the package Traefik loads for `.traefik.yml` `import` (the module root). `New` SHALL take Traefik’s constructor context and MUST NOT ignore it.

#### Scenario: Fork import still constructs
- **WHEN** Traefik loads `github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin`
- **THEN** `CreateConfig` and `New` exist on that package
- **AND** `New` receives a non-ignored context used as the reclaim holder

### Requirement: Bouncer does not own the stream
The per-router bouncer SHALL handle request policy (trusted IPs, ban/captcha pages, whether AppSec runs on pass, LAPI failure action, Redis fail-closed, and live-cache TTL) and MUST NOT start a process-wide stream ticker. The bouncer SHALL hold a `*lapi.Client` (nil when `crowdsecMode` is `appsec`) and a `*appsec.Client` (nil when AppSec is off). Two bouncers on one Client MAY apply distinct Redis fail-closed values. Two live routers on one Client that disagree on live-cache TTL last-write that TTL into the shared live cache. Per-router LAPI failure action is owned by `core_plugin_lapi_failure-action`; this leaf MUST NOT restate that owner SHALL.

#### Scenario: Second middleware does not start a second ticker
- **WHEN** two live stream configs disagree on update interval and share a LAPI key
- **THEN** one LAPI connection uses the interval from the first `New`
- **AND** the second `New` does not start another ticker

#### Scenario: Appsec mode skips LAPI Open
- **WHEN** `crowdsecMode` is `appsec` and `crowdsecAppsecEnabled` is true
- **THEN** `New` does not reclaim an `lapi.Client`
- **AND** `New` reclaims an `appsec.Client`
- **AND** the bouncer still holds that AppSec incarnation through a reclaim context derived from the constructor ctx

#### Scenario: Per-router live TTL last-writes the shared cache
- **WHEN** two live middlewares reclaim the same `lapi.Client` and set different `defaultDecisionSeconds`
- **THEN** each lookup uses the TTL that bouncer passed
- **AND** the shared live cache keeps the last written TTL for that key

### Requirement: A failed New releases the holders it already opened
`New` SHALL bind every reclaim `Open` it makes (decision store, LAPI client, AppSec client) to one context derived from the constructor context, and SHALL release that context on every path where it returns an error. A constructor that fails after an earlier `Open` succeeded MUST NOT leave that incarnation held: with zero table grace its `Close` hook SHALL run, and a stream ticker it started MUST NOT keep polling LAPI. The derived context SHALL stay a child of the constructor context, so cancelling Traefik's context still releases the holders of a `New` that succeeded. The success path MUST NOT release it.

#### Scenario: AppSec Open fails after a stream client was opened
- **WHEN** `crowdsecMode` is `stream`, the LAPI stream client opens, and `appsec.Open` then fails
- **THEN** `New` returns that error
- **AND** the LAPI incarnation is no longer held
- **AND** its stream ticker stops polling LAPI

#### Scenario: A successful New keeps its holder
- **WHEN** `New` returns a handler
- **THEN** the incarnations it opened are still held
- **AND** cancelling the constructor context releases them

### Requirement: New does not mutate the caller's Config
`New` SHALL snapshot the `*configuration.Config` Traefik passes before it normalises or resolves anything, and SHALL pass that snapshot to `lapi.Prepare`, `appsec.Prepare`, the reclaim `Open` calls, and `bouncer.New`. After `New` returns, the caller's struct MUST NOT carry a normalised `logLevel`, a resolved `crowdsecLapiKey` or `redisCachePassword`, a resolved `crowdsecAppsecKey`, or alone-mode's rewritten `crowdsecLapiHost` and forced `updateIntervalSeconds`. The snapshot is a shallow copy: `Config`'s slice and map fields stay shared with the caller, and the copy site SHALL say so.

#### Scenario: Resolved secrets stay out of the caller's struct
- **WHEN** `New` succeeds with a `crowdsecLapiKey` that resolves from a file and a lower-case `logLevel`
- **THEN** the caller's `*Config` still holds the unresolved key and the original `logLevel`

### Requirement: Captcha siteverify Timeout is the effective captcha seconds
When `bouncer.New` constructs the captcha provider `http.Client`, that client’s `Timeout` SHALL be `config.EffectiveHTTPTimeoutSeconds(config.CaptchaSiteverifyHTTPTimeoutSeconds)` seconds. It MUST NOT read raw `HTTPTimeoutSeconds` when the captcha override is non-zero. The client SHALL stay per-Bouncer. Implementations MUST NOT reclaim a captcha HTTP client and MUST NOT add `sync.Once` or a package-global siteverify client.

#### Scenario: Captcha override sets siteverify Timeout
- **WHEN** `bouncer.New` runs with a captcha provider set, `HTTPTimeoutSeconds` 10, and `CaptchaSiteverifyHTTPTimeoutSeconds` 1
- **THEN** the stored captcha siteverify `http.Client` Timeout is 1 second

#### Scenario: Captcha omit inherits the shared default
- **WHEN** `bouncer.New` runs with a captcha provider set, `HTTPTimeoutSeconds` 10, and `CaptchaSiteverifyHTTPTimeoutSeconds` 0
- **THEN** the stored captcha siteverify `http.Client` Timeout is 10 seconds
