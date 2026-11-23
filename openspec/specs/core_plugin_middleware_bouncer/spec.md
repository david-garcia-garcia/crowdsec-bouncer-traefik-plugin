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
The per-router bouncer SHALL hold five optional bound clients as `atomic.Value` fields (LAPI, AppSec, captcha, ModSec, and the rate limit), each able to hold a typed nil. Each field's stored concrete type SHALL stay `*reclaim.Box` (Yaegi). On every Watch publish into a bound field, the bouncer SHALL `Store` a new `*reclaim.Box{Value: .}` and MUST NOT assign `Box.Value` in place on a Box already published in that field. `ServeHTTP` SHALL `Load` those fields only and MUST NOT resolve instance names, Peek slot tables, or Open clients on the request path. Subscribers MUST NOT Bind reclaim on those clients. The bouncer SHALL read `lapiMode` from the loaded LAPI client on each request, not from a copy taken at `New`. When `bouncerEnabled` is false the handler SHALL call `next` without applying decisions while owners may still Open and publish.

#### Scenario: Nil LAPI client uses failure action for that leg
- **WHEN** the bouncer subscribed to LAPI but the loaded value is empty
- **THEN** the request uses that router's LAPI failure action for the LAPI leg
- **AND** no panic occurs

#### Scenario: Mode follows published client swap
- **WHEN** a subscriber's bound LAPI client changes from stream to live via Publish
- **THEN** the next request branches on the newly loaded client's mode

#### Scenario: Captcha binding is Load-only
- **WHEN** the bouncer subscribed to captcha
- **THEN** `ServeHTTP` Loads the captcha `atomic.Value` only
- **AND** it does not Open or reconstruct a captcha client on the request path

#### Scenario: ModSec binding is Load-only
- **WHEN** the bouncer subscribed to ModSec
- **THEN** `ServeHTTP` Loads the ModSec `atomic.Value` only
- **AND** it does not Open or reconstruct a ModSec client on the request path

#### Scenario: Rate-limit binding is Load-only
- **WHEN** the bouncer subscribed to a rate-limit instance
- **THEN** `ServeHTTP` Loads the rate-limit `atomic.Value` only
- **AND** it does not Open a rate-limit client, dial Redis, or compile buckets on the request path

#### Scenario: Bind update publishes a new Box
- **WHEN** a Watch notice updates an already-bound LAPI, AppSec, captcha, ModSec, or rate-limit field
- **THEN** the field's `atomic.Value` Stores a new `*reclaim.Box`
- **AND** the previous Box's `Value` field is not written in place
- **AND** concurrent ServeHTTP Unbox of that field does not panic from a torn `any`

### Requirement: A missing subscribed client uses that leg's failure action
A missing subscribed LAPI client SHALL use this router's LAPI failure action. A missing subscribed AppSec client SHALL use this router's AppSec failure action when the request reaches AppSec. A missing subscribed captcha client SHALL ban a captcha verdict. A missing subscribed ModSec client SHALL use this router's `bouncerModsecFailureAction` when the request reaches ModSec. A missing subscribed rate-limit client SHALL charge no bucket and the request SHALL continue to the AppSec step; the router has no rate-limit failure action of its own, because the policy is the owner's, and it logs the loss once (`core_plugin_ratelimit_client` "A subscriber logs the loss and return of its rate-limit owner"). The other legs log the loss once too ("A subscriber logs the loss and return of a connection"). `New` MUST NOT wait for a client to be published. A leg the bouncer did not subscribe to is not part of that check.

#### Scenario: AppSec-only subscriber ignores a missing LAPI client
- **WHEN** the bouncer subscribes only to AppSec and LAPI is not subscribed
- **THEN** a missing LAPI client does not by itself remediate the request

#### Scenario: Missing AppSec uses the AppSec failure action
- **WHEN** the bouncer subscribes to LAPI and AppSec, LAPI is published, and AppSec is not
- **AND** the request reaches AppSec
- **THEN** the AppSec failure action applies

#### Scenario: Unpublished subscribed captcha bans a captcha verdict
- **WHEN** the bouncer subscribes to captcha, captcha is not published, and the verdict is captcha
- **THEN** the response is a ban

#### Scenario: Missing ModSec uses the ModSec failure action
- **WHEN** the bouncer subscribes to ModSec, ModSec is not published, and `bouncerModsecFailureAction` is `ban`
- **AND** the request reaches ModSec
- **THEN** the response is the ban template with `ban:modsec-failure`

#### Scenario: Missing ModSec with the default passes
- **WHEN** the bouncer subscribes to ModSec, ModSec is not published, and `bouncerModsecFailureAction` is omitted
- **AND** the request reaches ModSec
- **THEN** the request reaches `next`

#### Scenario: Missing rate-limit client charges nothing
- **WHEN** the bouncer subscribes to rate-limit instance `shared` and no owner publishes it, or its owner went away
- **THEN** the request continues to the AppSec step without a remediation header
- **AND** no rate-limit drop is counted
- **AND** no WARN is logged for the request itself

### Requirement: A subscriber logs the loss and return of a connection
A router that subscribes to a LAPI, AppSec, ModSec, or captcha instance SHALL log WARN `crowdsec bouncer connection unavailable` (`traefikName`, `leg`, `instanceName`) once each time that leg moves to no published client, including a router built before its owner or naming an instance no loaded middleware shares, whether or not `Watch` delivers that first empty value (`New` traces a subscribed leg `Watch` delivered nothing to as unbound). It SHALL log INFO `crowdsec bouncer connection available` (`traefikName`, `leg`, `instanceName`, the bound client's `incarnation`) once, on the first bind of that leg after that WARN. Neither line SHALL be logged per request, on a repeated delivery of the same state, or when one client replaces another. The WARN SHALL be pending per Traefik middleware name and leg, not per `Bouncer`: a router of that name rebuilt while the leg is still missing SHALL NOT log a second WARN for the same instance name, the first bind of any router of that name and leg SHALL log the INFO, and a router of that name rebuilt without the leg SHALL drop the pending WARN without a line. The rate-limit leg SHALL keep its own lines (`core_plugin_ratelimit_client`) and SHALL NOT log these. What a request gets is unchanged ("A missing subscribed client uses that leg's failure action").

#### Scenario: A misspelled LAPI instance name warns once
- **WHEN** router `app-a` subscribes to LAPI instance `shared` and no loaded middleware publishes `shared`
- **THEN** WARN `crowdsec bouncer connection unavailable` with `traefikName` `app-a`, `leg` `lapi`, and `instanceName` `shared` is logged once, when `New` returns
- **AND** the same holds compiled into Traefik, whose `Watch` delivers nothing for that name, and under Traefik's interpreter, whose `Watch` delivers the typed nil: one WARN, never two
- **AND** every request gets the LAPI failure action without another WARN

#### Scenario: The connection returns
- **WHEN** that router later binds a published LAPI client
- **THEN** INFO `crowdsec bouncer connection available` with the client's `incarnation` is logged once
- **AND** binding the same client again or a replacing client logs neither line

#### Scenario: A rebuild during the outage does not warn again
- **WHEN** a Traefik reload builds a new `app-a` while `shared` is still unpublished
- **THEN** no second WARN is logged for `app-a` / `lapi` / `shared`
- **AND** the first bind of any `app-a` instance logs the INFO once

#### Scenario: Legs are pending separately
- **WHEN** `app-a` misses both its LAPI and its ModSec instance and only LAPI is published again
- **THEN** one WARN is logged per leg and one INFO for `lapi` only

### Requirement: Bouncer does not own the stream ticker
The per-router bouncer SHALL handle request policy (trusted IPs, ban/captcha pages, whether AppSec runs on pass, action rules, LAPI failure action, Redis fail-closed, and live-cache TTL) and MUST NOT start a process-wide stream ticker. Stream polling remains on the LAPI Client opened by an owner middleware.

#### Scenario: Second subscriber does not start a second ticker
- **WHEN** two bouncing middlewares subscribe to the same published LAPI stream client
- **THEN** only one stream ticker runs for that client incarnation

### Requirement: A failed New releases the holders it already opened
`New` SHALL bind every reclaim `Open` it makes (decision store, LAPI client, AppSec client, captcha client, ModSec client) to one context derived from the constructor context, and SHALL release that context on every path where it returns an error. A constructor that fails after an earlier `Open` succeeded MUST NOT leave that incarnation held: with zero table grace its `Close` hook SHALL run, and a stream ticker it started MUST NOT keep polling LAPI. The derived context SHALL stay a child of the constructor context, so cancelling Traefik's context still releases the holders of a `New` that succeeded. The success path MUST NOT release it.

#### Scenario: AppSec Open fails after a stream client was opened
- **WHEN** `lapiMode` is `stream`, the LAPI stream client opens, and `appsec.Open` then fails
- **THEN** `New` returns that error
- **AND** the LAPI incarnation is no longer held
- **AND** its stream ticker stops polling LAPI

#### Scenario: A successful New keeps its holder
- **WHEN** `New` returns a handler
- **THEN** the incarnations it opened are still held
- **AND** cancelling the constructor context releases them

#### Scenario: Captcha Open fails after LAPI was opened
- **WHEN** LAPI Opens and captcha Open then fails
- **THEN** `New` returns that error
- **AND** the LAPI incarnation is no longer held

#### Scenario: ModSec Open fails after LAPI was opened
- **WHEN** LAPI Opens and ModSec Open then fails
- **THEN** `New` returns that error
- **AND** the LAPI incarnation is no longer held

### Requirement: New does not mutate the caller's Config
`New` SHALL snapshot the `*configuration.Config` Traefik passes before it normalises or resolves anything, and SHALL pass that snapshot to `lapi.Prepare`, `appsec.Prepare`, `captcha.Prepare`, `modsecurity.Prepare`, the reclaim `Open` calls, and `bouncer.New`. After `New` returns, the caller's struct MUST NOT carry a normalised `logLevel`, a resolved `lapiKey` or `lapiRedisPassword`, a resolved `appsecKey`, or alone-mode's rewritten `lapiHost` and forced `lapiUpdateIntervalSeconds`. The snapshot is a shallow copy: `Config`'s slice and map fields stay shared with the caller, and the copy site SHALL say so.

#### Scenario: Resolved secrets stay out of the caller's struct
- **WHEN** `New` succeeds with a `lapiKey` that resolves from a file and a lower-case `logLevel`
- **THEN** the caller's `*Config` still holds the unresolved key and the original `logLevel`

### Requirement: Captcha siteverify Timeout is the effective captcha seconds
When an owning middleware constructs the captcha provider `http.Client`, that client’s `Timeout` SHALL be `config.CaptchaSiteverifyHTTPTimeoutSeconds` seconds. It MUST NOT read a shared or inherited timeout. Subscribers SHALL use the published client and MUST NOT construct a second siteverify client from leftover keys. `pkg/captcha` SHALL keep local parameter names (`siteKey`, `secretKey`, `gateSecret`); the owner SHALL pass `CaptchaSiteKey` into those arguments and MUST NOT grow a `bouncer` field on captcha.

#### Scenario: Captcha knob sets siteverify Timeout
- **WHEN** a captcha owner Opens with a captcha provider set and `CaptchaSiteverifyHTTPTimeoutSeconds` 1
- **THEN** the stored captcha siteverify `http.Client` Timeout is 1 second

#### Scenario: Captcha omit uses the captcha default
- **WHEN** a captcha owner Opens with a captcha provider set and the captcha timeout omitted
- **THEN** the stored captcha siteverify `http.Client` Timeout is 10 seconds

#### Scenario: Two subscribers share one siteverify client
- **WHEN** two bouncing middlewares subscribe to the same published captcha instance
- **THEN** both use that instance's siteverify `http.Client`
- **AND** neither constructs a local captcha client

### Requirement: Live stream and alone lookup uses one Store entry
When `lapiMode` is live, stream, or alone, and no matching action rule skipped LAPI and no matching action rule banned, the bouncer SHALL resolve memoized remediation through one `lapi.Client.LookupRemediation` that delegates to `Store.LookupRemediation`. It MUST NOT call `UsesLiveSnapshot`, MUST NOT branch between a live snapshot and a cache Client, and MUST NOT duplicate merge semantics in the bouncer. Stream and alone miss SHALL fall through to stream-healthy / failure-action. Live miss SHALL call `LiveLookup`, which returns `(kind, origin, error)` fields. None mode SHALL call `LiveLookup` every request (no memo read) unless a matching action rule skipped LAPI or a matching action rule banned. Action-rule skip and ban are owned by the action-rules requirement on this leaf; this lookup requirement MUST NOT restate those SHALL. `bouncer.New` SHALL copy `LapiDefaultDecisionSeconds` onto `Bouncer.defaultDecisionSeconds` and pass that into `LiveLookup`; the parameter name SHALL stay `defaultDecisionSeconds`.

#### Scenario: Stream mode uses Store lookup
- **WHEN** a stream bouncer handles a request and the DecisionStore is memory-backed
- **AND** no matching action rule skipped LAPI
- **AND** no matching action rule banned
- **THEN** remediation is resolved through `LookupRemediation` only

#### Scenario: Stream mode Redis uses the same entry
- **WHEN** a stream bouncer handles a request and the DecisionStore is Redis-backed
- **AND** no matching action rule skipped LAPI
- **AND** no matching action rule banned
- **THEN** remediation is resolved through the same `LookupRemediation`

#### Scenario: Live memo then LiveLookup
- **WHEN** `lapiMode` is live and the Store misses
- **AND** no matching action rule skipped LAPI
- **AND** no matching action rule banned
- **THEN** the bouncer calls `LiveLookup` and remediates from kind and origin fields

#### Scenario: None mode skips Store memo
- **WHEN** `lapiMode` is none
- **AND** no matching action rule skipped LAPI
- **AND** no matching action rule banned
- **THEN** the bouncer does not use a Store hit as the primary remediation check
- **AND** it calls `LiveLookup` for kind and origin

### Requirement: Client disconnect during AppSec body buffer is not a ban
When AppSec `Query` returns `ErrClientDisconnected`, the bouncer SHALL stop without calling origin, SHALL NOT write a ban template or `BouncerRemediationStatusCode`, and SHALL NOT increment LAPI dropped-request metrics. It SHALL log the disconnect at TRACE only. When `bouncerRemediationHeadersCustomName` is set, it SHALL set that response header to `error:client-disconnected` (kind `error`, reason `client-disconnected`; no third field) and MUST NOT call `WriteHeader`. `bouncerAppsecFailureAction` SHALL NOT change this path.

#### Scenario: Canceled upload is not a CrowdSec 403
- **WHEN** AppSec is enabled and the client disconnects while the readable body is buffered
- **THEN** origin is not called
- **AND** the response is not a ban
- **AND** if `bouncerRemediationHeadersCustomName` is `X-Remediation` the response header value is `error:client-disconnected`

### Requirement: Client body read failure during AppSec body buffer is a 400, not a ban
When AppSec `Query` returns `ErrClientBodyRead`, the bouncer SHALL answer HTTP 400 `Bad Request` without calling origin. It SHALL NOT write a ban template or `BouncerRemediationStatusCode`, and SHALL NOT increment LAPI dropped-request metrics. It SHALL log the read error at DEBUG. When `bouncerRemediationHeadersCustomName` is set, it SHALL set that response header to `error:client-body-read` (kind `error`, reason `client-body-read`; no third field). `bouncerAppsecFailureAction` SHALL NOT change this path.

#### Scenario: Slow upload past the read timeout is not a CrowdSec 403
- **WHEN** AppSec is enabled and the readable body cannot be read whole while the client is still connected
- **THEN** origin is not called
- **AND** the response is HTTP 400, not a ban
- **AND** no dropped request is counted
- **AND** if `bouncerRemediationHeadersCustomName` is `X-Remediation` the response header value is `error:client-body-read`

### Requirement: Captcha verdict without a published client is a ban
When the remediation kind is captcha and the loaded captcha binding is empty or not valid, the bouncer SHALL remediate as a ban. It MUST NOT construct a fallback local captcha client on the request path or in `bouncer.New`. A bounce-only middleware MUST NOT build a captcha client from leftover `captcha*` owner-read keys.

#### Scenario: Unpublished captcha bans
- **WHEN** the bouncer subscribed to captcha, the loaded captcha value is empty, and the verdict is captcha
- **THEN** the response is a ban
- **AND** no captcha challenge page is served

#### Scenario: Bounce-only leftover keys are not a client
- **WHEN** `captchaEnabled` is false, `captchaProvider` is set on this router, and no captcha client is published
- **THEN** `bouncer.New` does not construct a captcha client from those keys
- **AND** a captcha verdict remediates as a ban

### Requirement: Remediation header is not stored on the shared captcha client
The remediation header name SHALL stay on the Bouncer (`bouncerRemediationHeadersCustomName`). Challenge page, solved redirect, and captcha-kind responses SHALL write this router's header. The published `captcha.Client` MUST NOT store a remediation header copied from the owner. The bouncer SHALL pass the already-formatted challenge-page value into `ServeHTTP`. Pass 302 and Check-true form POST SHALL write `captcha:solved` inside captcha. Captcha MUST NOT import plugin origins or the closed reason table.

#### Scenario: Subscriber uses its own header name
- **WHEN** the owner sets `bouncerRemediationHeadersCustomName` to `X-Owner` and a subscriber of that captcha name sets `X-Route`
- **AND** the subscriber serves a captcha challenge
- **THEN** the response header name is `X-Route`
- **AND** it is not `X-Owner`

### Requirement: Unsubscribed captcha kind warns then bans
When the remediation kind is captcha and this bouncer did not subscribe to captcha, the bouncer SHALL emit WARN `crowdsec bouncer captcha unsubscribed` with attributes `leg` equal to `captcha` and `instanceName` (empty when unsubscribed) on every remediating request that reaches that path, then remediate as a ban. It MUST NOT emit an `ip` attribute on that WARN. It MUST NOT reconstruct the client address; identity stays `pkg/ip.GetRemoteIP` on `clientRequest`. It MUST NOT emit this WARN when the bouncer subscribed to captcha, including when the loaded captcha binding is empty or not valid. This WARN SHALL apply to every captcha-kind remediation that reaches the remediating handler (LAPI captcha kind, action-rule captcha, and the captcha failure action of the LAPI, AppSec, and ModSec legs). The rate-limit leg's captcha answers (a `captcha` bucket and the rate-limit failure action `captcha`) MUST NOT emit it; they log as `core_plugin_ratelimit_buckets` "Rate-limit captcha downgrades log on transitions" says.

#### Scenario: Bounce-only captcha kind warns then bans
- **WHEN** the bouncer did not subscribe to captcha
- **AND** the remediation kind is captcha
- **THEN** the response is a ban
- **AND** the log contains WARN `crowdsec bouncer captcha unsubscribed` with `leg` `captcha` and empty `instanceName`
- **AND** that record MUST NOT include `ip`

#### Scenario: Action-rule captcha on an unsubscribed router warns then bans
- **WHEN** the bouncer did not subscribe to captcha
- **AND** a matching action rule has `action: [captcha]` (or `[captcha, bypass]`)
- **AND** no leg banned
- **THEN** the response is a ban
- **AND** the log contains WARN `crowdsec bouncer captcha unsubscribed`

#### Scenario: Two remediating requests warn twice
- **WHEN** the bouncer did not subscribe to captcha
- **AND** two requests receive captcha kind
- **THEN** WARN `crowdsec bouncer captcha unsubscribed` is emitted twice

#### Scenario: Subscribed unpublished does not emit this warn
- **WHEN** the bouncer subscribed to captcha
- **AND** the loaded captcha value is empty
- **AND** the verdict is captcha
- **THEN** the response is a ban
- **AND** the log MUST NOT contain `crowdsec bouncer captcha unsubscribed`

#### Scenario: Rate-limit captcha answer on an unsubscribed router does not warn
- **WHEN** the bouncer did not subscribe to captcha
- **AND** a rate-limit bucket with `action: captcha` answers a request
- **THEN** the response is the `ratelimit` answer for that bucket
- **AND** the log MUST NOT contain `crowdsec bouncer captcha unsubscribed`

### Requirement: Ban page sets Cache-Control
When the bouncer writes the operator ban page, the response SHALL set `Cache-Control` to `no-cache, no-store`. It MUST set that header before `WriteHeader`. HEAD and empty-body (nil template) bans SHALL carry the same header.

#### Scenario: GET ban includes Cache-Control
- **WHEN** `handleBanServeHTTP` writes a GET ban
- **THEN** `Cache-Control` is `no-cache, no-store`

#### Scenario: HEAD ban includes Cache-Control
- **WHEN** `handleBanServeHTTP` writes a HEAD ban
- **THEN** `Cache-Control` is `no-cache, no-store`
- **AND** the body is empty

#### Scenario: Nil template ban includes Cache-Control
- **WHEN** `handleBanServeHTTP` writes a ban and the ban template is nil
- **THEN** `Cache-Control` is `no-cache, no-store`

### Requirement: Structured remediation header values

When `bouncerRemediationHeadersCustomName` is non-empty, each remediating response this bouncer writes SHALL set that header to a structured value `kind:reason` or `kind:reason:origin`. `:` is the field separator. Consumers SHALL split at most three fields. There is no space after `:`. Empty header name SHALL still omit the header. Pass, skip-to-next from action rules, trusted IP, failure-action passthrough, remap-to-pass, widget-asset passthrough, valid gate-cookie origin GET, disabled bouncer, and startup 503 MUST NOT set this header. The plugin MUST NOT emit `allow: pass`. The plugin MUST NOT add a public config key for this header.

Closed reasons never take a third field, except `lapi` (the metrics origin) and `ratelimit` (the bucket name). The closed vocabulary is:

| Header | Meaning |
| ------ | ------- |
| `ban:rules` | Matching action rule applied ban |
| `ban:lapi` | CrowdSec decision type ban, empty metrics origin |
| `ban:lapi:<origin>` | CrowdSec decision type ban; third field is header-safe metrics origin |
| `ban:lapi-failure` | LAPI down / unpublished, fail-closed ban |
| `ban:stream-unhealthy` | Stream miss + unhealthy, fail-closed ban |
| `ban:cache-fail` | Redis/cache fail-closed |
| `ban:appsec` | AppSec JSON `action: ban` |
| `ban:appsec-challenge-empty` | AppSec `action: challenge` with empty body (fail-closed to ban page) |
| `ban:appsec-action-empty` | AppSec action other than `allow` / `ban` / `captcha` / `challenge` with empty body (fail-closed to ban page) |
| `ban:appsec-failure` | AppSec down / unusable verdict, fail-closed ban |
| `ban:modsec` | CRS sidecar copied 3xx/4xx block |
| `ban:modsec-failure` | ModSec sidecar down / unpublished, failure action `ban` (RemediationReason `MODSEC`) |
| `ban:ratelimit:<bucket>` | A rate-limit bucket with `action: ratelimit` answered, or a `captcha` bucket answered as `ratelimit` (`bypassCaptcha`, or no usable captcha); third field is the bucket name |
| `ban:ratelimit-failure` | Rate-limit counter could not answer, failure action `ban` |
| `ban:captcha-downgrade` | Kind was captcha; this router served a ban page (unsubscribed / unpublished / invalid captcha client) |
| `captcha:rules` | Matching action rule applied captcha |
| `captcha:lapi` / `captcha:lapi:<origin>` | CrowdSec decision type captcha (same origin encoding) |
| `captcha:lapi-failure` | LAPI fail-closed captcha |
| `captcha:stream-unhealthy` | Stream fail-closed captcha |
| `captcha:appsec-failure` | AppSec fail-closed captcha |
| `captcha:modsec-failure` | ModSec sidecar down / unpublished, failure action `captcha` |
| `captcha:ratelimit:<bucket>` | Router captcha page for a rate-limit bucket with `action: captcha`; third field is the bucket name |
| `captcha:ratelimit-failure` | Rate-limit counter could not answer, failure action `captcha` |
| `captcha:ratelimit` | Router captcha page for a challenge-marker POST that the rate-limit leg's captcha gate answered with the challenge again (no bucket answered) |
| `captcha:appsec` | Router captcha page for an AppSec JSON `action: captcha`, or for a challenge-marker POST that AppSec let through |
| `captcha:challenge` | AppSec bot-detection `action: challenge` with non-empty body |
| `captcha:solved` | 302 after a successful solve (token pass or second-tab captcha-form POST) |
| `error:client-disconnected` | Client gone during an AppSec or ModSec body copy |
| `error:client-body-read` | Client body could not be read whole during an AppSec or ModSec body copy (HTTP 400) |

LAPI third field SHALL be the usage-metrics origin already returned by `LookupRemediation` / `LiveLookup` (`MetricsOrigin`), after strip of CR/LF/TAB and rewriting only the prefix `lists:` → `lists_`. Empty origin omits the third field. The plugin MUST NOT globally replace remaining colons. The plugin MUST NOT change `MetricsOrigin` or DecisionStore packing. Plugin origins, including `plugin:rules:<name>`, and AppSec specials are reason tokens, never a third field. A metrics origin that starts with `plugin:rules:` SHALL map to closed reason `rules` (no third field). A metrics origin that starts with `plugin:ratelimit:` SHALL map to reason `ratelimit` with the rest of the origin (the bucket name) as the third field, after the same CR/LF/TAB strip. Bucket names cannot contain `:`, so the value still splits into at most three fields. Origin `plugin:ratelimit_failure` SHALL map to closed reason `ratelimit-failure` (no third field). Origin `plugin:ratelimit` (no bucket) SHALL map to reason `ratelimit` with no third field. Client address stays `pkg/ip.GetRemoteIP` on `clientRequest`; this header MUST NOT reconstruct identity.

The bouncer SHALL format ban, AppSec relay, disconnect, captcha-downgrade, and captcha challenge-page values. `pkg/captcha` MUST NOT own the closed table. Challenge page SHALL receive the already-formatted value. Pass 302 and Check-true form POST SHALL write `captcha:solved` with no third field.

#### Scenario: LAPI crowdsec origin on a ban
- **WHEN** `bouncerRemediationHeadersCustomName` is `X-Remediation`
- **AND** lookup is CrowdSec ban with metrics origin `crowdsec`
- **THEN** the response header `X-Remediation` is `ban:lapi:crowdsec`

#### Scenario: Lists origin uses lists_ only
- **WHEN** `bouncerRemediationHeadersCustomName` is set
- **AND** lookup is CrowdSec ban with metrics origin `lists:firehol_level1`
- **THEN** the header value is `ban:lapi:lists_firehol_level1`

#### Scenario: Empty LAPI origin omits the third field
- **WHEN** `bouncerRemediationHeadersCustomName` is set
- **AND** lookup is CrowdSec ban with empty metrics origin
- **THEN** the header value is `ban:lapi`

#### Scenario: Action-rule ban is rules
- **WHEN** `bouncerRemediationHeadersCustomName` is set
- **AND** a matching action rule applies ban
- **THEN** the header value is `ban:rules`

#### Scenario: Action-rule captcha is rules
- **WHEN** `bouncerRemediationHeadersCustomName` is set
- **AND** a matching action rule applies captcha
- **THEN** the header value is `captcha:rules`

#### Scenario: Captcha-downgrade on an unsubscribed router
- **WHEN** `bouncerRemediationHeadersCustomName` is set
- **AND** the remediation kind is captcha
- **AND** this bouncer did not subscribe to captcha
- **THEN** the response is a ban
- **AND** the header value is `ban:captcha-downgrade`

#### Scenario: GetRemoteIP error is HTTP 502
- **WHEN** `GetRemoteIP` returns an error
- **THEN** the response status is 502
- **AND** the body is plain text `Bad Gateway`
- **AND** the remediation header is not set

#### Scenario: Pass path still omits the header
- **WHEN** `bouncerRemediationHeadersCustomName` is set
- **AND** the request is trusted, skipped to next by action rules, remapped to pass, or otherwise calls `next` without a remediating writer
- **THEN** that response does not set the remediation header

#### Scenario: Empty name still disables
- **WHEN** `bouncerRemediationHeadersCustomName` is empty
- **AND** the bouncer writes a ban page
- **THEN** no structured remediation header is set

#### Scenario: AppSec captcha verdict is captcha:appsec
- **WHEN** `bouncerRemediationHeadersCustomName` is set
- **AND** AppSec returns `action` `captcha` and this router serves its captcha challenge page
- **THEN** the header value is `captcha:appsec`

#### Scenario: Bodyless unknown AppSec action is ban:appsec-action-empty
- **WHEN** `bouncerRemediationHeadersCustomName` is set
- **AND** AppSec returns an action other than `allow`, `ban`, `captcha`, or `challenge` with empty `user_body_content`
- **THEN** the header value is `ban:appsec-action-empty`

#### Scenario: ModSec copied block is ban:modsec
- **WHEN** `bouncerRemediationHeadersCustomName` is set
- **AND** the sidecar returns HTTP 403
- **THEN** the header value is `ban:modsec`

#### Scenario: ModSec failure ban is ban:modsec-failure
- **WHEN** `bouncerRemediationHeadersCustomName` is set
- **AND** the sidecar is unreachable and `bouncerModsecFailureAction` is `ban`
- **THEN** the header value is `ban:modsec-failure`
- **AND** the usage-metrics origin is `plugin:modsec_failure`

#### Scenario: Rate-limit deny carries the bucket name
- **WHEN** `bouncerRemediationHeadersCustomName` is set
- **AND** bucket `login` with `action: ratelimit` is over its limit
- **THEN** the header value is `ban:ratelimit:login`

#### Scenario: Captcha bucket challenge carries the bucket name
- **WHEN** `bouncerRemediationHeadersCustomName` is set
- **AND** bucket `per-ip-soft` with `action: captcha` answers with this router's captcha challenge page
- **THEN** the header value is `captcha:ratelimit:per-ip-soft`

#### Scenario: Rate-limit failure is a closed reason
- **WHEN** `bouncerRemediationHeadersCustomName` is set
- **AND** the rate-limit counter returns an error and `rateLimitFailureAction` is `ban`
- **THEN** the header value is `ban:ratelimit-failure`

#### Scenario: Rate-limit log bucket sets no header
- **WHEN** `bouncerRemediationHeadersCustomName` is set
- **AND** only a `log` bucket is over its limit
- **THEN** the response from the backend does not carry the remediation header

### Requirement: Action rules fold every matching row

The bouncer SHALL expose one public Config list `bouncerActionRules`. Default empty (omit or empty list) SHALL match nothing (setting off). Each row SHALL have `name`, `action`, and the same request predicates as dest `httprule.Rule` (`method`, `path`, `host`, `headers`, `cookies`). An omitted predicate, or `path` / `host` / `method` empty after trim, or an empty `headers` / `cookies` map, SHALL mean any for that predicate. Set predicates on one row SHALL all match (AND).

`name` SHALL be required, unique in the list, and MUST NOT contain `:`. `action` SHALL be a required non-empty array of tokens `bypass`, `bypassLapi`, `bypassAppsec`, `bypassModsec`, `bypassCaptcha`, `bypassRateLimit`, `ban`, `captcha`. Order in the array SHALL NOT matter. `bypass` SHALL skip LAPI, AppSec, and ModSec. `bypass` SHALL NOT skip the rate limit. Duplicates, unknown tokens, an empty array, or an omitted action SHALL fail `New`. `ban` MUST be the only token in that array; `ban` combined with `captcha` or any skip SHALL fail `New`. `captcha` combined with `bypassCaptcha` in one array SHALL fail `New`. The action array is not a match predicate.

All matching rows SHALL contribute. This is not first-match-wins. List order SHALL pick the origin name only when two rows share the same winning remediation (first matching `ban`, else first matching `captcha`).

After a `GetRemoteIP` error (HTTP 502, not a ban), `IncProcessed`, and the trusted-IP skip, ServeHTTP SHALL collect every matching row. Trusted clients MUST NOT hit these rules. A `GetRemoteIP` error MUST NOT be saved by a matching skip.

- Any matching `ban` SHALL remediate immediately as ban. LAPI, the rate limit, AppSec, and ModSec MUST NOT run. Metrics origin SHALL be `plugin:rules:<name>` where `<name>` is the first matching ban row. `remediation=ban`. A skip on another matching row MUST NOT weaken this ban. Closed remediation-header reason SHALL be `rules` (no third field) when that header is configured.
- Else fold every match: `bypass` or `bypassLapi` SHALL skip LAPI; `bypass` or `bypassAppsec` SHALL skip AppSec; `bypass` or `bypassModsec` SHALL skip ModSec; `bypassRateLimit` SHALL skip the rate limit; any `captcha` token SHALL set a captcha flag. Skips SHALL add; they MUST NOT cancel each other or a captcha flag. Any `bypassCaptcha` token SHALL set a captcha-bypass flag, and that flag SHALL clear the captcha flag (requirement "bypassCaptcha lets a request through where a captcha would be served"). `bypassCaptcha` skips no leg. Two exceptions drop a skip: a row with a `path` predicate skips nothing (LAPI, AppSec, ModSec, or the rate limit) on a path with more than one reading (requirement "Action-rule skips need a single-reading path"), and no row skips AppSec under `/crowdsec-internal/challenge/` (`core_plugin_appsec_bot-detection`, "Action rules cannot skip AppSec on the challenge prefix").
- A LAPI skip SHALL skip `LookupRemediation`, `LiveLookup`, missing-subscribed-LAPI failure action, and stream/alone unhealthy failure action.
- An AppSec skip SHALL skip AppSec `Query` and the AppSec body buffer on that path.
- A ModSec skip SHALL skip sidecar inspect, body buffer, the admission gate, and the missing-subscribed-ModSec failure action.
- A rate-limit skip SHALL skip every bucket: no bucket is charged, none can deny, and the rate-limit failure action does not apply.
- `captcha` MUST NOT return immediately. Legs that were not skipped SHALL still run. An active LAPI ban, or a fail-closed ban from that leg (lookup error, stream/alone unhealthy, failure action `ban`), SHALL prevail over the captcha rule and SHALL keep that leg's origin, not `plugin:rules:`. An AppSec `ban` verdict, or an AppSec failure-action `ban`, SHALL prevail over the captcha rule and SHALL keep origin `appsec` / `plugin:appsec_failure`. Those drops SHALL log WARN `warnCaptchaSuperseded` with attributes `name` (the first matching captcha row that lost) and dest `ip`. The plugin MUST NOT log attr `header` for this WARN.
- An AppSec `challenge` with non-empty body is not a ban and MUST NOT override the captcha rule (MUST NOT relay; apply the plugin gate). An AppSec `challenge` with empty `UserBodyContent` SHALL stay dest fail-closed ban (`ban:appsec-challenge-empty`, origin `appsec`) and therefore SHALL prevail over the captcha rule like `ban`. Empty-challenge dest when no captcha rule matched MUST NOT change.
- A CrowdSec captcha decision SHALL be unchanged: the rule MUST NOT replace that outcome, the metrics origin SHALL stay the CrowdSec origin, and AppSec for that decision SHALL stay after a valid captcha gate cookie, not before the challenge page.
- If no leg banned and a captcha rule matched, ServeHTTP SHALL serve the existing captcha gate. Origin `plugin:rules:<name>` of the first matching captcha row, `remediation=captcha`, only when that rule is what is applied. A valid gate cookie SHALL still pass. After the cookie is valid, AppSec SHALL still run unless a matching `bypass` or `bypassAppsec` skipped it.
- When a captcha rule matched and AppSec was not skipped, AppSec Query SHALL run before serving the plugin captcha gate so an AppSec ban can stop an unsolved visitor.
- The only way for a captcha rule to avoid a LAPI ban is a matching `bypass` or `bypassLapi` (same row or another matching row). The only way to avoid an AppSec ban is a matching `bypass` or `bypassAppsec`. The only way to avoid a ModSec copied block is a matching `bypass` or `bypassModsec`.
- Captcha with no usable captcha client MUST NOT fail `New`. It SHALL downgrade to a ban at request time with dest WARN `crowdsec bouncer captcha unsubscribed`. That drop's origin SHALL still be `plugin:rules:<name>`, `remediation=ban`.
- Skips MUST NOT increment `dropped`. `recordProcessed` SHALL still run.
- These rules MUST NOT enter LAPI ownership keys or AppSec identity keys.
- The plugin MUST NOT compile rules on the request path. `ValidateParams` SHALL compile and discard; `bouncer.New` SHALL compile again to store.
- A WebSocket handshake GET SHALL be inspected like any other GET.

Path SHALL be Go RE2, unanchored `MatchString` against `req.URL.Path` (percent-decoded, not slash-normalized, not the query). The plugin MUST NOT insert `^` or `$`. The plugin MUST NOT rebuild path from `RequestURI`, `EscapedPath`, or AppSec forwarded URI. Host SHALL NOT be part of the path match. A Host header rule SHALL read `req.Header`.

Host SHALL be optional Go RE2, unanchored `MatchString` against the hostname of `req.Host`. When `net.SplitHostPort(req.Host)` succeeds, the match text SHALL be that host (`example.com:443` → `example.com`, `[::1]:443` → `::1`). When it fails, the match text SHALL be `req.Host` unchanged. The plugin MUST NOT insert `^` or `$`. The plugin MUST NOT read the Host header map. The plugin MUST NOT include scheme, port, or path in the match text. Omit or empty after trim SHALL match any host. There is no leading `!` negation on host. A host-only rule SHALL be valid.

Method SHALL be Go RE2, unanchored `MatchString` against `req.Method`. The plugin MUST NOT insert `^` or `$`, MUST NOT lowercase the method, and MUST NOT force `(?i)`. Omit or empty after trim SHALL match any method. An optional single leading `!` outside the pattern, stripped before compile, SHALL negate the match (`!POST`, `!^POST$`). Go RE2 only (no lookahead).

Headers SHALL treat names case-insensitively via `textproto.CanonicalMIMEHeaderKey`. Several names SHALL be AND. An empty pattern SHALL mean that header is present with any value. A non-empty pattern SHALL be RE2 against each value of `req.Header[canonical]`; one matching value SHALL be enough.

Cookies SHALL use the same predicate shape as headers against that cookie's value. Cookie names SHALL be case-sensitive. The plugin MUST NOT parse the Cookie header for a list that has no cookie predicate. When that list has a cookie predicate, ServeHTTP SHALL parse Cookie once per request for that list.

#### Scenario: Empty list still looks up
- **WHEN** `bouncerActionRules` is omitted or empty
- **AND** the bouncer subscribed to LAPI
- **THEN** ServeHTTP still consults `LookupRemediation` or `LiveLookup` as today

#### Scenario: Bypass LAPI path skips stream store and unhealthy failure
- **WHEN** `bouncerActionRules` contains `{name: healthz, path: "^/healthz$", action: [bypassLapi]}`
- **AND** `req.URL.Path` is `/healthz`
- **AND** `lapiMode` is stream or alone
- **THEN** ServeHTTP does not call `LookupRemediation`
- **AND** it does not apply a store hit
- **AND** it does not take stream-unhealthy failure action

#### Scenario: Bypass AppSec path skips Query on the pass path
- **WHEN** `bouncerActionRules` contains `{name: healthz, path: "^/healthz$", action: [bypassAppsec]}`
- **AND** `req.URL.Path` is `/healthz`
- **AND** the bouncer subscribed to AppSec
- **AND** the request reaches the pass path
- **THEN** ServeHTTP does not call AppSec `Query`
- **AND** it does not buffer the body for AppSec
- **AND** it calls `next`

#### Scenario: Bypass does not skip the other leg
- **WHEN** a matching row is `{action: [bypassLapi]}` and no matching row skips AppSec
- **AND** the bouncer subscribed to AppSec
- **AND** the request reaches the pass path
- **THEN** AppSec `Query` still runs

#### Scenario: All matching rows contribute skips
- **WHEN** `bouncerActionRules` contains `{name: a, path: "^/ab", action: [bypassLapi]}` then `{name: b, path: "^/ab", action: [bypassAppsec]}`
- **AND** `req.URL.Path` is `/ab`
- **THEN** ServeHTTP skips LAPI and skips AppSec
- **AND** matching does not stop at the first row

#### Scenario: Ban wins immediately over a matching skip
- **WHEN** `bouncerActionRules` contains `{name: skip, path: "^/x$", action: [bypass]}` then `{name: deny, path: "^/x$", action: [ban]}`
- **AND** `req.URL.Path` is `/x`
- **THEN** the response is the ban page
- **AND** origin is `plugin:rules:deny`
- **AND** ServeHTTP does not consult LAPI, AppSec, or ModSec

#### Scenario: First matching ban name wins
- **WHEN** `bouncerActionRules` contains `{name: first, path: "^/x$", action: [ban]}` then `{name: second, path: "^/x$", action: [ban]}`
- **AND** `req.URL.Path` is `/x`
- **THEN** origin is `plugin:rules:first`

#### Scenario: Captcha plus bypass skips both legs then captchas
- **WHEN** `bouncerActionRules` contains `{name: challenge-health, path: "^/healthz$", action: [captcha, bypass]}`
- **AND** `req.URL.Path` is `/healthz`
- **AND** the captcha gate cookie is absent or invalid
- **THEN** ServeHTTP does not consult LAPI or AppSec
- **AND** the response is the captcha challenge
- **AND** origin is `plugin:rules:challenge-health`
- **AND** `remediation=captcha`

#### Scenario: Captcha alone still allows a LAPI ban
- **WHEN** `bouncerActionRules` contains `{name: c, headers: {X-Crowdsec-Decision: "^c$"}, action: [captcha]}`
- **AND** the request has `X-Crowdsec-Decision: c`
- **AND** stream lookup is ban for that client
- **THEN** the response is the ban page
- **AND** origin is the LAPI origin, not `plugin:rules:`
- **AND** the log includes WARN `warnCaptchaSuperseded` with `name` `c`

#### Scenario: Captcha plus bypassLapi still allows an AppSec ban
- **WHEN** `bouncerActionRules` contains `{name: c, path: "^/x$", action: [captcha, bypassLapi]}`
- **AND** `req.URL.Path` is `/x`
- **AND** AppSec returns `action: ban`
- **THEN** the response is the ban page
- **AND** origin is `appsec`
- **AND** the log includes WARN `warnCaptchaSuperseded` with `name` `c`

#### Scenario: Non-empty AppSec challenge does not override captcha rule
- **WHEN** a captcha rule matched and AppSec was not skipped
- **AND** AppSec returns `action: challenge` with non-empty body
- **AND** the captcha gate cookie is absent or invalid
- **THEN** the response is the plugin captcha challenge
- **AND** origin is `plugin:rules:<name>` of the first matching captcha row
- **AND** ServeHTTP does not relay the AppSec envelope

#### Scenario: Empty AppSec challenge body still bans over captcha rule
- **WHEN** a captcha rule matched and AppSec was not skipped
- **AND** AppSec returns `action: challenge` with empty body
- **THEN** the response is the ban page
- **AND** origin is `appsec`

#### Scenario: AppSec Query runs before the plugin captcha gate
- **WHEN** a captcha rule matched and AppSec was not skipped
- **AND** the captcha gate cookie is absent or invalid
- **THEN** ServeHTTP calls AppSec `Query` before serving the plugin captcha page

#### Scenario: Unanchored path matches a substring
- **WHEN** `bouncerActionRules` contains `{name: health, path: "health", action: [bypassLapi]}`
- **AND** `req.URL.Path` is `/unhealthy`
- **THEN** the LAPI leg is skipped

#### Scenario: Header match is each value unanchored
- **WHEN** `bouncerActionRules` contains `{name: decision-ban, headers: {X-Crowdsec-Decision: "^b$"}, action: [ban]}`
- **AND** the request has `X-Crowdsec-Decision: b`
- **THEN** the response is the ban page
- **AND** origin is `plugin:rules:decision-ban`

#### Scenario: Bare b pattern is not exact
- **WHEN** `bouncerActionRules` contains `{name: loose, headers: {X-Crowdsec-Decision: "b"}, action: [ban]}`
- **AND** the request has `X-Crowdsec-Decision: abc`
- **THEN** the response is the ban page

#### Scenario: Trusted IP still skips the whole plugin
- **WHEN** the client address is in `bouncerClientTrustedIPs`
- **AND** an action rule would match
- **THEN** the request reaches the next handler
- **AND** ServeHTTP does not apply action rules

#### Scenario: GetRemoteIP failure is not saved by a skip
- **WHEN** GetRemoteIP returns an error
- **AND** an action rule would match with `action: [bypass]`
- **THEN** the response status is 502
- **AND** usage-metrics `dropped` is not incremented

#### Scenario: Skip does not increment dropped
- **WHEN** a matching row is `{action: [bypass]}` and no ban or captcha matched
- **THEN** ServeHTTP calls `next`
- **AND** usage-metrics `dropped` is not incremented for that skip
- **AND** `processed` is incremented

#### Scenario: Unusable captcha client on a captcha rule bans with rules origin
- **WHEN** a captcha rule matched, no leg banned, and this bouncer did not subscribe to captcha
- **THEN** the response is a ban
- **AND** origin is `plugin:rules:<name>` of that captcha row
- **AND** `remediation=ban`
- **AND** the log contains WARN `crowdsec bouncer captcha unsubscribed`

#### Scenario: Valid gate cookie still passes a captcha rule
- **WHEN** a captcha rule matched, no leg banned, and `Check` is true for that request and client address
- **AND** the request is not a captcha-form POST
- **THEN** the request reaches the next handler
- **AND** AppSec still runs unless a matching skip skipped it

#### Scenario: bypassRateLimit skips only the rate limit
- **WHEN** a matching row is `{path: "^/health$", action: [bypassRateLimit]}`
- **AND** a catch-all bucket is over its limit for this client
- **THEN** the request is not denied by the rate limit
- **AND** LAPI and AppSec still run for that request

#### Scenario: bypass does not skip the rate limit
- **WHEN** a matching row is `{path: "^/api/", action: [bypass]}`
- **AND** a catch-all bucket is over its limit for this client
- **THEN** the rate limit denies the request

#### Scenario: Ban mixed with bypassRateLimit fails New
- **WHEN** a row has `action: [ban, bypassRateLimit]`
- **THEN** `New` fails with `action: ban must be alone`

### Requirement: Action-rule skips need a single-reading path
A matching action row that has a `path` predicate SHALL contribute its `bypass`, `bypassLapi`, `bypassAppsec`, and `bypassModsec` skips only when the request path has a single reading. The path has a single reading when `req.URL.EscapedPath()` equals `req.URL.Path` (the client percent-encoded nothing), every byte is one of `A-Z a-z 0-9 - . _ ~ ! $ & ' ( ) + , = : @ /`, `path.Clean` (keeping a trailing slash) leaves it unchanged, and no segment is only dots. Otherwise that row's skips SHALL be ignored for the request, because its regex read one path and the backend may serve another (a Java servlet backend reads `/healthz/..;/admin` as `/admin`; an IIS backend reads `\` as `/`). That row's `captcha` token SHALL still apply. A row without a `path` predicate SHALL keep its skips. `ban` rows SHALL be unchanged. `ActionMatch.AmbiguousPathName` SHALL name the first row whose skips were ignored, and ServeHTTP SHALL log TRACE `foldActionRules` with attr `ambiguousPathRule`. Anchoring the regex does not prevent this; the check is on the request path, not on the pattern. Upstream: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/413 (single-reading rule of `crowdsecAppsecExcludedLocations`).

#### Scenario: Java path-parameter traversal does not skip AppSec
- **WHEN** `bouncerActionRules` contains `{name: healthz, path: "^/healthz(/|$)", action: [bypassAppsec]}`
- **AND** the request path is `/healthz/..;/admin` (or `/healthz/%2E%2E;/admin`, `/healthz/..%5Cadmin`, `/healthz%2Fadmin`, `/healthz/%252e%252e/admin`)
- **THEN** AppSec `Query` runs for that request

#### Scenario: Plain subpath still skips
- **WHEN** `bouncerActionRules` contains `{name: healthz, path: "^/healthz(/|$)", action: [bypassAppsec]}`
- **AND** the request path is `/healthz/live`
- **THEN** the AppSec leg is skipped

#### Scenario: Captcha token survives an ambiguous path
- **WHEN** a matching row is `{path: "^/healthz/", action: [captcha, bypassLapi]}`
- **AND** the request path is `/healthz/..;/admin`
- **THEN** the captcha rule applies
- **AND** the LAPI leg is not skipped

#### Scenario: Rule without a path predicate keeps its skip
- **WHEN** a matching row is `{host: "^internal\.example$", action: [bypassLapi]}`
- **AND** the request path is `/healthz/..;/admin`
- **THEN** the LAPI leg is skipped

#### Scenario: Bypass ModSec path skips sidecar
- **WHEN** `bouncerActionRules` contains `{name: healthz, path: "^/healthz$", action: [bypassModsec]}`
- **AND** `req.URL.Path` is `/healthz`
- **AND** the bouncer subscribed to ModSec
- **AND** the query string would otherwise trip CRS
- **THEN** ServeHTTP does not call the sidecar
- **AND** it does not buffer the body for ModSec

#### Scenario: Bypass skips ModSec as well
- **WHEN** a matching row is `{action: [bypass]}`
- **AND** the bouncer subscribed to LAPI, AppSec, and ModSec
- **THEN** ServeHTTP skips LAPI, AppSec, and ModSec

### Requirement: ServeHTTP runs ModSec after AppSec and captcha write
When the bouncer subscribed to ModSec and no earlier writer returned, ServeHTTP SHALL run ModSec inspect after LAPI and AppSec and after an existing captcha-flag write (unsolved captcha still short-circuits before ModSec). A valid captcha gate cookie SHALL fall through to ModSec then `next`. Trusted clients SHALL skip LAPI, AppSec, and ModSec. Action-rule ban SHALL return before any WAF. AppSec FailureAction ban on an admitted miss SHALL return before ModSec. AppSec gate skip SHALL NOT return: ServeHTTP SHALL continue to ModSec when subscribed. A ModSec copied block, HTTP 413, or a ModSec failure action `ban` (or an unsolved `captcha`) SHALL return before `next`. A ModSec gate skip SHALL NOT return and SHALL NOT apply the ModSec failure action: ServeHTTP SHALL continue to `next`.

#### Scenario: CRS runs after AppSec allow
- **WHEN** the bouncer subscribed to AppSec and ModSec
- **AND** AppSec returns allow
- **AND** no captcha flag wrote
- **THEN** ModSec inspect runs before `next`

#### Scenario: Unsolved captcha does not call ModSec
- **WHEN** a captcha rule matched and the gate cookie is absent
- **AND** no leg banned
- **THEN** the response is the captcha challenge
- **AND** ModSec inspect does not run

#### Scenario: AppSec gate skip continues to ModSec
- **WHEN** the AppSec Gate denies Allow
- **AND** the bouncer subscribed to ModSec
- **THEN** AppSec is not called
- **AND** ModSec inspect still runs

#### Scenario: ModSec gate skip continues to next
- **WHEN** the ModSec Gate denies admission
- **AND** `bouncerModsecFailureAction` is `ban`
- **THEN** the sidecar is not called
- **AND** the request reaches `next` with no remediation header

### Requirement: bypassCaptcha lets a request through where a captcha would be served
`bouncerActionRules` SHALL accept the action token `bypassCaptcha`. It is for requests that cannot solve a captcha, such as machine-to-machine API calls. When at least one matching row carries it, ServeHTTP MUST NOT serve this router's captcha gate for that request: wherever the gate would have written a challenge, a solved-form redirect, or a captcha downgrade ban, nothing is written and the request continues to the next leg, then to `next`. `ActionMatch.BypassCaptchaName` SHALL name the first matching row with the token; empty SHALL mean none.

`bypassCaptcha` skips no leg. The LAPI lookup and the AppSec `Query` SHALL still run, so a ban still bans.

The captcha sources that continue instead of writing SHALL be:

- a LAPI decision whose applied kind is captcha (cache lookup and live lookup);
- the LAPI failure action `captcha` (missing subscribed client, live lookup error, unhealthy stream);
- an AppSec `captcha` verdict;
- the AppSec failure action `captcha` (missing client, or a query failure);
- the ModSec failure action `captcha` (missing client, or no sidecar verdict);
- the rate-limit failure action `captcha` (counter error);
- a captcha challenge-form POST that AppSec let through;
- a captcha challenge-form POST that the rate-limit step hands to the captcha gate.

A bypassed captcha MUST NOT increment `dropped`, MUST NOT set the remediation header, and MUST NOT log WARN `crowdsec bouncer captcha unsubscribed`. It SHALL log TRACE `bypassCaptcha` with attrs `ip` and `name` (the rule). The bypass SHALL apply before the captcha downgrade: on a router with no usable captcha client the request also continues, it is not banned.

When a captcha-bypass flag is set, `ActionMatch.CaptchaName` SHALL be empty even when another matching row carries `captcha`. No captcha rule applies to that request, and WARN `warnCaptchaSuperseded` MUST NOT be logged for it.

A rate-limit bucket with `action: captcha` is the one exception: on a request a `bypassCaptcha` row matches, that bucket SHALL answer as a `ratelimit` bucket (`rateLimitStatusCode`, `Retry-After`, `ban:ratelimit:<bucket>`) instead of letting the request through, so a rate limit does not become unlimited (`core_plugin_ratelimit_buckets`).

Everything that is not this router's captcha gate SHALL be unchanged: a `ban` row; a LAPI ban; a fail-closed ban from the LAPI leg; an AppSec `ban` verdict or failure-action `ban`; an AppSec `challenge` (relayed when it carries a page, `ban:appsec-challenge-empty` when it does not, although its header value starts with `captcha:`); and any other AppSec action.

A row with a `path` predicate SHALL apply `bypassCaptcha` on every request its regex matches. The single-reading path requirement ("Action-rule skips need a single-reading path") covers `bypass`, `bypassLapi`, `bypassAppsec`, and `bypassModsec` only. On a path with more than one reading, a row `{action: [bypassCaptcha, bypassLapi]}` SHALL still bypass the captcha and SHALL NOT skip LAPI. The operator relies on Traefik for the path: Traefik resolves `.` and `..` segments and decodes `%2e` before the plugin runs, and by default does not reject `%2F`, `%5C`, `%3B`, or double encoding (`knowledge/research/ext_traefik_entrypoints_request-path/`).

#### Scenario: LAPI captcha decision continues
- **WHEN** `bouncerActionRules` contains `{name: api, path: "^/api/", action: [bypassCaptcha]}`
- **AND** the request path is `/api/items` and the client has an active LAPI `captcha` decision
- **THEN** no captcha page is written and the remediation header is not set
- **AND** the AppSec leg runs, then `next`

#### Scenario: LAPI ban still bans
- **WHEN** the same rule matches and the client has an active LAPI `ban` decision
- **THEN** ServeHTTP remediates as ban

#### Scenario: AppSec captcha verdict continues
- **WHEN** the same rule matches and AppSec answers `captcha`
- **THEN** no captcha page is written
- **AND** `next` is called

#### Scenario: AppSec ban verdict still bans
- **WHEN** the same rule matches and AppSec answers `ban`
- **THEN** ServeHTTP remediates as ban with origin `appsec`

#### Scenario: AppSec challenge is still relayed
- **WHEN** the same rule matches and AppSec answers `challenge` with a non-empty body
- **THEN** the challenge page is relayed

#### Scenario: Failure action captcha continues
- **WHEN** the same rule matches, the LAPI failure action is `captcha`, and no LAPI client is published
- **THEN** no captcha page is written
- **AND** the AppSec leg runs, then `next`

#### Scenario: Router without a usable captcha is not banned
- **WHEN** the same rule matches, the client has an active LAPI `captcha` decision, and this router did not subscribe to a captcha
- **THEN** the request is not banned
- **AND** WARN `crowdsec bouncer captcha unsubscribed` is not logged

#### Scenario: bypassCaptcha wins over a captcha rule
- **WHEN** `bouncerActionRules` contains `{name: gate, host: "^shop\.example$", action: [captcha]}` and `{name: api, path: "^/api/", action: [bypassCaptcha]}`
- **AND** both rows match the request
- **THEN** `ActionMatch.CaptchaName` is empty and `ActionMatch.BypassCaptchaName` is `api`
- **AND** no captcha page is written

#### Scenario: Captcha bucket answers as a rate limit
- **WHEN** the rule `{name: api, path: "^/api/", action: [bypassCaptcha]}` matches
- **AND** a rate-limit bucket `per-ip-soft` with `action: captcha` is over its limit for the client
- **THEN** the response is `rateLimitStatusCode` with `ban:ratelimit:per-ip-soft`
- **AND** `next` is not called

#### Scenario: Request outside the rule still gets the captcha
- **WHEN** the rule is `{name: api, path: "^/api/", action: [bypassCaptcha]}` and the request path is `/catalog`
- **AND** the client has an active LAPI `captcha` decision
- **THEN** the captcha gate is served

#### Scenario: Ambiguous path still bypasses the captcha
- **WHEN** a matching row is `{name: api, path: "^/api/", action: [bypassCaptcha, bypassLapi]}`
- **AND** the request path is `/api/..;/admin`
- **THEN** `ActionMatch.BypassCaptchaName` is `api`
- **AND** the LAPI leg is not skipped
- **AND** `ActionMatch.AmbiguousPathName` is `api`

### Requirement: The rate limit runs between the LAPI step and the AppSec step
When the router subscribes to a rate-limit instance (`bouncerEnabled` and a `rateLimitInstanceName`, filled with the Traefik name on an owner), ServeHTTP SHALL run the rate-limit step after the LAPI step and before the AppSec step. Requests that never reach it SHALL NOT be charged to any bucket: a `GetRemoteIP` error, a trusted client, a disabled bouncer, a matching action-rule `ban`, and a request the LAPI step answered (a CrowdSec ban, an unsolved CrowdSec captcha, a LAPI fail-closed ban or captcha). A request the LAPI step let through (no decision, a valid captcha gate cookie, a LAPI skip, failure action `passthrough`) SHALL reach the rate-limit step. The action-rule captcha gate and the AppSec query SHALL run after the rate-limit step, so a request a bucket answered never reaches AppSec. When the router does not subscribe to a rate-limit instance, the request path SHALL be unchanged.

The rate-limit step SHALL NOT increment `processed` a second time.

#### Scenario: LAPI ban is not charged
- **WHEN** CrowdSec has a ban for the client
- **AND** a catch-all bucket allows 1 request per minute
- **THEN** every request of that client gets the LAPI ban page
- **AND** the bucket counter for that client does not move

#### Scenario: Denied request does not reach AppSec
- **WHEN** a `ratelimit` bucket is over its limit for the client
- **AND** AppSec is enabled on the router
- **THEN** the response is the `ratelimit` answer
- **AND** AppSec is not queried

#### Scenario: Trusted client is not charged
- **WHEN** the client address is in `bouncerClientTrustedIps`
- **THEN** the request reaches the backend and no bucket counter moves

#### Scenario: Action-rule captcha comes after the rate limit
- **WHEN** a `captcha` action rule matches the request and a `ratelimit` bucket is over its limit for the client
- **THEN** the response is the `ratelimit` answer, not the captcha page
- **AND** WARN `warnCaptchaSuperseded` is logged with attribute `name` of that captcha rule

#### Scenario: Owner without bouncerEnabled charges nothing
- **WHEN** a middleware sets `rateLimitEnabled` and leaves `bouncerEnabled` false
- **THEN** it publishes its rate-limit client
- **AND** requests through it reach `next` without being charged
