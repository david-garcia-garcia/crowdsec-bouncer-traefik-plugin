## Purpose

Traefik Yaegi loads `CreateConfig` and `New` from the module-root package. `New` binds its reclaim holders to a context derived from the constructor context, works on a snapshot of the config Traefik owns, and returns a per-router Bouncer that holds bound clients as `atomic.Value` fields, applies request policy, and MUST NOT start a process-wide stream ticker.

## Requirements

### Requirement: Yaegi constructors stay on the module-root package
The plugin SHALL export `CreateConfig` and `New` from the package Traefik loads for `.traefik.yml` `import` (the module root). `New` SHALL take Traefik’s constructor context and MUST NOT ignore it.

#### Scenario: Fork import still constructs
- **WHEN** Traefik loads `github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin`
- **THEN** `CreateConfig` and `New` exist on that package
- **AND** `New` receives a non-ignored context used as the reclaim holder

### Requirement: Bouncer binds clients through atomic late bind
The per-router bouncer SHALL hold two optional bound clients as `atomic.Value` fields (LAPI and AppSec), each able to hold a typed nil. `ServeHTTP` SHALL `Load` those fields only and MUST NOT resolve instance names, Peek slot tables, or Open clients on the request path. Subscribers MUST NOT Bind reclaim on those clients. The bouncer SHALL read `crowdsecMode` from the loaded LAPI client on each request, not from a copy taken at `New`. When `enabled` is false the handler SHALL call `next` without applying decisions while owners may still Open and publish.

#### Scenario: Nil LAPI client uses failure action for that leg
- **WHEN** the bouncer subscribed to LAPI but the loaded value is empty and `streamStartupBlock` is false
- **THEN** the request uses that router's LAPI failure action for the LAPI leg
- **AND** no panic occurs

#### Scenario: Mode follows published client swap
- **WHEN** a subscriber's bound LAPI client changes from stream to live via Publish
- **THEN** the next request branches on the newly loaded client's mode

### Requirement: Stream startup block guards subscribed backends on the request path
When `streamStartupBlock` is true, before calling `next` or applying decisions the bouncer SHALL check every leg it subscribed to (LAPI and/or AppSec independently). For each subscribed leg, if the loaded client is not published (typed nil), `ServeHTTP` SHALL return HTTP 503 and MUST NOT call `next`. When `streamStartupBlock` is false, a missing subscribed client SHALL use that leg's failure action instead. The check MUST NOT block `New`. A leg the bouncer did not subscribe to is not part of the guard.

#### Scenario: AppSec-only subscriber does not 503 for missing LAPI
- **WHEN** the bouncer subscribes only to AppSec and LAPI is not subscribed
- **THEN** a missing LAPI client does not cause 503 solely for LAPI

#### Scenario: Both legs subscribed one missing yields 503 when block true
- **WHEN** the bouncer subscribes to LAPI and AppSec, `streamStartupBlock` is true, and AppSec is not published
- **THEN** every request returns 503 until AppSec is published

### Requirement: Bouncer does not own the stream ticker
The per-router bouncer SHALL handle request policy (trusted IPs, ban/captcha pages, whether AppSec runs on pass, LAPI failure action, Redis fail-closed, and live-cache TTL) and MUST NOT start a process-wide stream ticker. Stream polling remains on the LAPI Client opened by an owner middleware.

#### Scenario: Second subscriber does not start a second ticker
- **WHEN** two bouncing middlewares subscribe to the same published LAPI stream client
- **THEN** only one stream ticker runs for that client incarnation

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
