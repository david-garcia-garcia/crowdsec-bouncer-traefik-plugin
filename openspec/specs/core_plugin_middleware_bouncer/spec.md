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
The per-router bouncer SHALL handle request policy (trusted IPs, ban/captcha pages, whether AppSec runs on pass, LAPI failure action, Redis fail-closed, and live-cache TTL) and MUST NOT start a process-wide stream ticker. The bouncer SHALL hold a `*lapi.Client` (nil when `crowdsecMode` is `appsec`) and a `*appsec.Client` (nil when AppSec is off). Two bouncers on one Client MAY apply distinct Redis fail-closed values. Two live routers on one Client that disagree on live-cache TTL last-write that TTL into the shared live cache. Per-router LAPI failure action is owned by `core_plugin_lapi_failure-action`; this leaf MUST NOT restate that owner SHALL. Exclusive Traefik-name ownership of the LAPI DecisionStore is owned by `core_plugin_lapi_reclaim-key`; this leaf MUST NOT invent a second identity registry.

#### Scenario: Second middleware does not start a second ticker
- **WHEN** two live stream configs use the same Traefik name, disagree on update interval, and share a LAPI key
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

### Requirement: A second different Traefik name fails New
When `crowdsecMode` is live, stream, or none (not `appsec`), `New` SHALL fail if a DecisionStore for that LAPI session already exists with a different `createdBy` (`core_plugin_lapi_reclaim-key`). Same Traefik name on many routers MUST still share. Failed `New` SHALL still release bindCtx. AppSec Open is unchanged.

#### Scenario: Different Traefik name on the same LAPI key fails New
- **WHEN** a live stream middleware named `foo` already holds the DecisionStore for a LAPI URL and key
- **AND** a later `New` for that same LAPI URL and key uses Traefik name `bar`
- **THEN** `New` returns an error
- **AND** bindCtx is released
- **AND** the first middleware’s store and Client stay held

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

### Requirement: Live stream and alone lookup uses one Store entry
When `crowdsecMode` is live, stream, or alone, and a configured `crowdsecDecisionHeader` does not force `b` on this request, the bouncer SHALL resolve memoized remediation through one `lapi.Client.LookupRemediation` that delegates to `Store.LookupRemediation`. It MUST NOT call `UsesLiveSnapshot`, MUST NOT branch between a live snapshot and a cache Client, and MUST NOT duplicate merge semantics in the bouncer. Stream and alone miss SHALL fall through to stream-healthy / failure-action. Live miss SHALL call `LiveLookup`, which returns `(kind, origin, error)` fields. None mode SHALL call `LiveLookup` every request (no memo read) unless that same header forced `b`. Forced `b` or `c` is owned by `core_plugin_middleware_forced-decision`; this leaf MUST NOT restate that owner SHALL.

#### Scenario: Stream mode uses Store lookup
- **WHEN** a stream bouncer handles a request and the DecisionStore is memory-backed
- **AND** `crowdsecDecisionHeader` is empty or the named header is not exact trimmed `b`
- **THEN** remediation is resolved through `LookupRemediation` only

#### Scenario: Stream mode Redis uses the same entry
- **WHEN** a stream bouncer handles a request and the DecisionStore is Redis-backed
- **AND** `crowdsecDecisionHeader` is empty or the named header is not exact trimmed `b`
- **THEN** remediation is resolved through the same `LookupRemediation`

#### Scenario: Live memo then LiveLookup
- **WHEN** `crowdsecMode` is live and the Store misses
- **AND** `crowdsecDecisionHeader` is empty or the named header is not exact trimmed `b`
- **THEN** the bouncer calls `LiveLookup` and remediates from kind and origin fields

#### Scenario: None mode skips Store memo
- **WHEN** `crowdsecMode` is none
- **AND** `crowdsecDecisionHeader` is empty or the named header is not exact trimmed `b`
- **THEN** the bouncer does not use a Store hit as the primary remediation check
- **AND** it calls `LiveLookup` for kind and origin

### Requirement: Client disconnect during AppSec body buffer is not a ban
When AppSec `Query` returns `ErrClientDisconnected`, the bouncer SHALL stop without calling origin, SHALL NOT write a ban template or `RemediationStatusCode`, and SHALL NOT increment LAPI dropped-request metrics. It SHALL log the disconnect at TRACE only. When `remediationHeadersCustomName` is set, it SHALL set that response header to `error:client-disconnected` and MUST NOT call `WriteHeader`. `crowdsecAppsecFailureAction` SHALL NOT change this path.

#### Scenario: Canceled upload is not a CrowdSec 403
- **WHEN** AppSec is enabled and the client disconnects while the readable body is buffered
- **THEN** origin is not called
- **AND** the response is not a ban
- **AND** if `remediationHeadersCustomName` is `X-Remediation` the response header value is `error:client-disconnected`
