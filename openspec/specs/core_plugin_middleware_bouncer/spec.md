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
The per-router bouncer SHALL hold three optional bound clients as `atomic.Value` fields (LAPI, AppSec, and captcha), each able to hold a typed nil. Each field's stored concrete type SHALL stay `*reclaim.Box` (Yaegi). On every Watch publish into a bound field, the bouncer SHALL `Store` a new `*reclaim.Box{Value: …}` and MUST NOT assign `Box.Value` in place on a Box already published in that field. `ServeHTTP` SHALL `Load` those fields only and MUST NOT resolve instance names, Peek slot tables, or Open clients on the request path. Subscribers MUST NOT Bind reclaim on those clients. The bouncer SHALL read `lapiMode` from the loaded LAPI client on each request, not from a copy taken at `New`. When `bouncerEnabled` is false the handler SHALL call `next` without applying decisions while owners may still Open and publish.

#### Scenario: Nil LAPI client uses failure action for that leg
- **WHEN** the bouncer subscribed to LAPI but the loaded value is empty and `startupBlock` is false
- **THEN** the request uses that router's LAPI failure action for the LAPI leg
- **AND** no panic occurs

#### Scenario: Mode follows published client swap
- **WHEN** a subscriber's bound LAPI client changes from stream to live via Publish
- **THEN** the next request branches on the newly loaded client's mode

#### Scenario: Captcha binding is Load-only
- **WHEN** the bouncer subscribed to captcha
- **THEN** `ServeHTTP` Loads the captcha `atomic.Value` only
- **AND** it does not Open or reconstruct a captcha client on the request path

#### Scenario: Bind update publishes a new Box
- **WHEN** a Watch notice updates an already-bound LAPI, AppSec, or captcha field
- **THEN** the field's `atomic.Value` Stores a new `*reclaim.Box`
- **AND** the previous Box's `Value` field is not written in place
- **AND** concurrent ServeHTTP Unbox of that field does not panic from a torn `any`

### Requirement: Stream startup block guards subscribed backends on the request path
When `bouncerStartupBlock` is true, before calling `next` or applying decisions the bouncer SHALL check every leg it subscribed to (LAPI, AppSec, and captcha independently). For each subscribed leg, if the loaded client is not published (typed nil), `ServeHTTP` SHALL return HTTP 503 and MUST NOT call `next`. When `bouncerStartupBlock` is false, a missing subscribed LAPI or AppSec client SHALL use that leg's failure action instead, and a missing subscribed captcha client SHALL ban a captcha verdict. The check MUST NOT block `New`. A leg the bouncer did not subscribe to is not part of the guard. The Bouncer field name SHALL be `startupBlock` (not `streamStartupBlock`).

#### Scenario: AppSec-only subscriber does not 503 for missing LAPI
- **WHEN** the bouncer subscribes only to AppSec and LAPI is not subscribed
- **THEN** a missing LAPI client does not cause 503 solely for LAPI

#### Scenario: Both legs subscribed one missing yields 503 when block true
- **WHEN** the bouncer subscribes to LAPI and AppSec, `bouncerStartupBlock` is true, and AppSec is not published
- **THEN** every request returns 503 until AppSec is published

#### Scenario: Unpublished subscribed captcha yields 503 when block true
- **WHEN** the bouncer subscribes to captcha, `bouncerStartupBlock` is true, and captcha is not published
- **THEN** every request returns 503 until captcha is published

### Requirement: Bouncer does not own the stream ticker
The per-router bouncer SHALL handle request policy (trusted IPs, ban/captcha pages, whether AppSec runs on pass, request bypass rules, LAPI failure action, Redis fail-closed, and live-cache TTL) and MUST NOT start a process-wide stream ticker. Stream polling remains on the LAPI Client opened by an owner middleware.

#### Scenario: Second subscriber does not start a second ticker
- **WHEN** two bouncing middlewares subscribe to the same published LAPI stream client
- **THEN** only one stream ticker runs for that client incarnation

### Requirement: A failed New releases the holders it already opened
`New` SHALL bind every reclaim `Open` it makes (decision store, LAPI client, AppSec client, captcha client) to one context derived from the constructor context, and SHALL release that context on every path where it returns an error. A constructor that fails after an earlier `Open` succeeded MUST NOT leave that incarnation held: with zero table grace its `Close` hook SHALL run, and a stream ticker it started MUST NOT keep polling LAPI. The derived context SHALL stay a child of the constructor context, so cancelling Traefik's context still releases the holders of a `New` that succeeded. The success path MUST NOT release it.

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

### Requirement: New does not mutate the caller's Config
`New` SHALL snapshot the `*configuration.Config` Traefik passes before it normalises or resolves anything, and SHALL pass that snapshot to `lapi.Prepare`, `appsec.Prepare`, the reclaim `Open` calls, and `bouncer.New`. After `New` returns, the caller's struct MUST NOT carry a normalised `logLevel`, a resolved `lapiKey` or `lapiRedisPassword`, a resolved `appsecKey`, or alone-mode's rewritten `lapiHost` and forced `lapiUpdateIntervalSeconds`. The snapshot is a shallow copy: `Config`'s slice and map fields stay shared with the caller, and the copy site SHALL say so.

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
When `lapiMode` is live, stream, or alone, and a configured `bouncerDecisionHeader` does not force `b` on this request, and no LAPI bypass rule matches, the bouncer SHALL resolve memoized remediation through one `lapi.Client.LookupRemediation` that delegates to `Store.LookupRemediation`. It MUST NOT call `UsesLiveSnapshot`, MUST NOT branch between a live snapshot and a cache Client, and MUST NOT duplicate merge semantics in the bouncer. Stream and alone miss SHALL fall through to stream-healthy / failure-action. Live miss SHALL call `LiveLookup`, which returns `(kind, origin, error)` fields. None mode SHALL call `LiveLookup` every request (no memo read) unless that same header forced `b` or a LAPI bypass rule matches. Forced `b` or `c` is owned by `core_plugin_middleware_forced-decision`; this leaf MUST NOT restate that owner SHALL. `bouncer.New` SHALL copy `LapiDefaultDecisionSeconds` onto `Bouncer.defaultDecisionSeconds` and pass that into `LiveLookup`; the parameter name SHALL stay `defaultDecisionSeconds`.

#### Scenario: Stream mode uses Store lookup
- **WHEN** a stream bouncer handles a request and the DecisionStore is memory-backed
- **AND** `bouncerDecisionHeader` is empty or the named header is not exact trimmed `b`
- **AND** `bouncerLapiBypassRules` is empty or does not match
- **THEN** remediation is resolved through `LookupRemediation` only

#### Scenario: Stream mode Redis uses the same entry
- **WHEN** a stream bouncer handles a request and the DecisionStore is Redis-backed
- **AND** `bouncerDecisionHeader` is empty or the named header is not exact trimmed `b`
- **AND** `bouncerLapiBypassRules` is empty or does not match
- **THEN** remediation is resolved through the same `LookupRemediation`

#### Scenario: Live memo then LiveLookup
- **WHEN** `lapiMode` is live and the Store misses
- **AND** `bouncerDecisionHeader` is empty or the named header is not exact trimmed `b`
- **AND** `bouncerLapiBypassRules` is empty or does not match
- **THEN** the bouncer calls `LiveLookup` and remediates from kind and origin fields

#### Scenario: None mode skips Store memo
- **WHEN** `lapiMode` is none
- **AND** `bouncerDecisionHeader` is empty or the named header is not exact trimmed `b`
- **AND** `bouncerLapiBypassRules` is empty or does not match
- **THEN** the bouncer does not use a Store hit as the primary remediation check
- **AND** it calls `LiveLookup` for kind and origin

### Requirement: Client disconnect during AppSec body buffer is not a ban
When AppSec `Query` returns `ErrClientDisconnected`, the bouncer SHALL stop without calling origin, SHALL NOT write a ban template or `BouncerRemediationStatusCode`, and SHALL NOT increment LAPI dropped-request metrics. It SHALL log the disconnect at TRACE only. When `bouncerRemediationHeadersCustomName` is set, it SHALL set that response header to `error:client-disconnected` (kind `error`, reason `client-disconnected`; no third field) and MUST NOT call `WriteHeader`. `bouncerAppsecFailureAction` SHALL NOT change this path.

#### Scenario: Canceled upload is not a CrowdSec 403
- **WHEN** AppSec is enabled and the client disconnects while the readable body is buffered
- **THEN** origin is not called
- **AND** the response is not a ban
- **AND** if `bouncerRemediationHeadersCustomName` is `X-Remediation` the response header value is `error:client-disconnected`

### Requirement: Captcha verdict without a published client is a ban
When the remediation kind is captcha and the loaded captcha binding is empty or not valid, the bouncer SHALL remediate as a ban. It MUST NOT construct a fallback local captcha client on the request path or in `bouncer.New`. A bounce-only middleware MUST NOT build a captcha client from leftover `captcha*` owner-read keys.

#### Scenario: Unpublished captcha with startup block off bans
- **WHEN** the bouncer subscribed to captcha, `bouncerStartupBlock` is false, the loaded captcha value is empty, and the verdict is captcha
- **THEN** the response is a ban
- **AND** no captcha challenge page is served

#### Scenario: Bounce-only leftover keys are not a client
- **WHEN** `captchaEnabled` is false, `captchaProvider` is set on this router, and no captcha client is published
- **THEN** `bouncer.New` does not construct a captcha client from those keys
- **AND** a captcha verdict remediates as a ban when startup block is false

### Requirement: Remediation header is not stored on the shared captcha client
The remediation header name SHALL stay on the Bouncer (`bouncerRemediationHeadersCustomName`). Challenge page, solved redirect, and captcha-kind responses SHALL write this router's header. The published `captcha.Client` MUST NOT store a remediation header copied from the owner. The bouncer SHALL pass the already-formatted challenge-page value into `ServeHTTP`. Pass 302 and Check-true form POST SHALL write `captcha:solved` inside captcha. Captcha MUST NOT import plugin origins or the closed reason table.

#### Scenario: Subscriber uses its own header name
- **WHEN** the owner sets `bouncerRemediationHeadersCustomName` to `X-Owner` and a subscriber of that captcha name sets `X-Route`
- **AND** the subscriber serves a captcha challenge
- **THEN** the response header name is `X-Route`
- **AND** it is not `X-Owner`

### Requirement: Unsubscribed captcha kind warns then bans
When the remediation kind is captcha and this bouncer did not subscribe to captcha, the bouncer SHALL emit WARN `crowdsec bouncer captcha unsubscribed` with attributes `leg` equal to `captcha` and `instanceName` (empty when unsubscribed) on every remediating request that reaches that path, then remediate as a ban. It MUST NOT emit an `ip` attribute on that WARN. It MUST NOT reconstruct the client address; identity stays `pkg/ip.GetRemoteIP` on `clientRequest`. It MUST NOT emit this WARN when the bouncer subscribed to captcha, including when the loaded captcha binding is empty or not valid. Subscribed-unpublished with `bouncerStartupBlock` true SHALL stay HTTP 503 plus WARN `crowdsec bouncer backend missing`. This WARN SHALL apply to every captcha-kind remediation that reaches the remediating handler (LAPI captcha kind, forced header `c`, captcha failure-action).

#### Scenario: Bounce-only captcha kind warns then bans
- **WHEN** the bouncer did not subscribe to captcha
- **AND** the remediation kind is captcha
- **THEN** the response is a ban
- **AND** the log contains WARN `crowdsec bouncer captcha unsubscribed` with `leg` `captcha` and empty `instanceName`
- **AND** that record MUST NOT include `ip`

#### Scenario: Forced captcha header on an unsubscribed router warns then bans
- **WHEN** the bouncer did not subscribe to captcha
- **AND** `bouncerDecisionHeader` forces `c`
- **AND** lookup is not a ban
- **THEN** the response is a ban
- **AND** the log contains WARN `crowdsec bouncer captcha unsubscribed`

#### Scenario: Two remediating requests warn twice
- **WHEN** the bouncer did not subscribe to captcha
- **AND** two requests receive captcha kind
- **THEN** WARN `crowdsec bouncer captcha unsubscribed` is emitted twice

#### Scenario: Subscribed unpublished does not emit this warn
- **WHEN** the bouncer subscribed to captcha
- **AND** `bouncerStartupBlock` is false
- **AND** the loaded captcha value is empty
- **AND** the verdict is captcha
- **THEN** the response is a ban
- **AND** the log MUST NOT contain `crowdsec bouncer captcha unsubscribed`

#### Scenario: Subscribed unpublished startup block stays backend missing
- **WHEN** the bouncer subscribed to captcha
- **AND** `bouncerStartupBlock` is true
- **AND** captcha is not published
- **THEN** every request returns 503
- **AND** the log contains WARN `crowdsec bouncer backend missing`
- **AND** the log MUST NOT contain `crowdsec bouncer captcha unsubscribed`

### Requirement: Per-leg request bypass rules skip that CrowdSec leg
The bouncer SHALL expose public Config lists `bouncerAppsecBypassRules` and `bouncerLapiBypassRules` (same rule shape). Default empty (omit or empty list) SHALL skip nothing for that leg. Each rule MAY set `method`, `path`, `host`, `headers`, and `cookies`. An omitted field, or `path` / `host` / `method` empty after trim, or an empty `headers` / `cookies` map, SHALL mean any for that predicate. Set predicates on one rule SHALL all match (AND). Rules in one list SHALL be OR; the first matching rule wins. A LAPI match SHALL skip `LookupRemediation`, `LiveLookup`, missing-subscribed-LAPI failure action, and stream/alone unhealthy failure action, and SHALL continue at `passOrForcedCaptcha`. An AppSec match SHALL skip AppSec `Query` and the AppSec body buffer and SHALL call `next`. The two lists SHALL be independent. Bypass SHALL run after startup block, GetRemoteIP, trusted-IP skip, and forced `b`. Forced `c` SHALL still apply on the pass path after a LAPI match. These lists MUST NOT enter LAPI ownership or AppSec identity keys. The plugin MUST NOT compile rules on the request path. `recordProcessed` SHALL still run for a bypassed request. A WebSocket handshake GET SHALL be inspected like any other GET.

Path SHALL be Go RE2, unanchored `MatchString` against `req.URL.Path` (percent-decoded, not slash-normalized, not the query). The plugin MUST NOT insert `^` or `$`. The plugin MUST NOT rebuild path from `RequestURI`, `EscapedPath`, or AppSec forwarded URI. Host SHALL NOT be part of the path match. A Host header rule SHALL read `req.Header`.

Host SHALL be optional Go RE2, unanchored `MatchString` against the hostname of `req.Host`. When `net.SplitHostPort(req.Host)` succeeds, the match text SHALL be that host (`example.com:443` → `example.com`, `[::1]:443` → `::1`). When it fails, the match text SHALL be `req.Host` unchanged. The plugin MUST NOT insert `^` or `$`. The plugin MUST NOT read the Host header map. The plugin MUST NOT include scheme, port, or path in the match text. Omit or empty after trim SHALL match any host. There is no leading `!` negation on host. A host-only rule SHALL be valid.

Method SHALL be Go RE2, unanchored `MatchString` against `req.Method`. The plugin MUST NOT insert `^` or `$`, MUST NOT lowercase the method, and MUST NOT force `(?i)`. Omit or empty after trim SHALL match any method. An optional single leading `!` outside the pattern, stripped before compile, SHALL negate the match (`!POST`, `!^POST$`). Go RE2 only (no lookahead).

Headers SHALL treat names case-insensitively via `textproto.CanonicalMIMEHeaderKey`. Several names SHALL be AND. An empty pattern SHALL mean that header is present with any value. A non-empty pattern SHALL be RE2 against each value of `req.Header[canonical]`; one matching value SHALL be enough.

Cookies SHALL use the same predicate shape as headers against that cookie's value. Cookie names SHALL be case-sensitive. The plugin MUST NOT parse the Cookie header for a list that has no cookie predicate. When that list has a cookie predicate, ServeHTTP SHALL parse Cookie once per request for that list.

#### Scenario: Empty LAPI list still looks up
- **WHEN** `bouncerLapiBypassRules` is omitted or empty
- **AND** the bouncer subscribed to LAPI
- **AND** `bouncerDecisionHeader` is empty or the named header is not exact trimmed `b`
- **THEN** ServeHTTP still consults `LookupRemediation` or `LiveLookup` as today

#### Scenario: LAPI path rule skips stream store and unhealthy failure
- **WHEN** `bouncerLapiBypassRules` contains `{path: "^/healthz$"}`
- **AND** `req.URL.Path` is `/healthz`
- **AND** `lapiMode` is stream or alone
- **THEN** ServeHTTP does not call `LookupRemediation`
- **AND** it does not apply a store hit
- **AND** it does not take stream-unhealthy failure action
- **AND** it continues at `passOrForcedCaptcha`

#### Scenario: LAPI path rule skips live and none lookup
- **WHEN** `bouncerLapiBypassRules` contains `{path: "^/healthz$"}`
- **AND** `req.URL.Path` is `/healthz`
- **AND** `lapiMode` is live or none
- **THEN** ServeHTTP does not call `LiveLookup`
- **AND** it continues at `passOrForcedCaptcha`

#### Scenario: Unanchored path matches a substring
- **WHEN** `bouncerLapiBypassRules` contains `{path: "health"}`
- **AND** `req.URL.Path` is `/unhealthy`
- **THEN** the LAPI leg is skipped

#### Scenario: Host is not in the path match
- **WHEN** `bouncerLapiBypassRules` contains `{path: "example.com://health"}`
- **AND** `req.Host` is `example.com` and `req.URL.Path` is `/health`
- **THEN** the LAPI leg is not skipped for that rule

#### Scenario: Query string is not in the path
- **WHEN** `bouncerAppsecBypassRules` contains `{path: "^/healthz$"}`
- **AND** `req.URL.Path` is `/healthz` and the request has query `a=1`
- **AND** the bouncer subscribed to AppSec
- **AND** the request reaches `handleNextServeHTTP`
- **THEN** ServeHTTP does not call AppSec `Query`
- **AND** it calls `next`

#### Scenario: AppSec path rule skips Query on the pass path
- **WHEN** `bouncerAppsecBypassRules` contains `{path: "^/healthz$"}`
- **AND** `req.URL.Path` is `/healthz`
- **AND** the bouncer subscribed to AppSec
- **AND** the request reaches `handleNextServeHTTP`
- **THEN** ServeHTTP does not call AppSec `Query`
- **AND** it does not buffer the body for AppSec
- **AND** it calls `next`

#### Scenario: LAPI bypass does not skip AppSec
- **WHEN** a LAPI rule matches and no AppSec rule matches
- **AND** the bouncer subscribed to AppSec
- **AND** the request reaches the pass path
- **THEN** AppSec `Query` still runs

#### Scenario: AppSec bypass does not skip LAPI
- **WHEN** an AppSec rule matches and no LAPI rule matches
- **AND** the bouncer subscribed to LAPI
- **AND** `bouncerDecisionHeader` is empty or the named header is not exact trimmed `b`
- **THEN** ServeHTTP still consults `LookupRemediation` or `LiveLookup` as today

#### Scenario: Forced b still bans before LAPI bypass
- **WHEN** `bouncerDecisionHeader` forces `b`
- **AND** a LAPI bypass rule would match this request
- **THEN** the response is the ban page
- **AND** ServeHTTP does not apply the LAPI bypass skip

#### Scenario: Forced c still captchas after LAPI bypass
- **WHEN** a LAPI bypass rule matches
- **AND** `bouncerDecisionHeader` forces `c`
- **AND** lookup is skipped
- **THEN** the pass path still applies forced captcha

#### Scenario: Host-only rule matches that hostname
- **WHEN** `bouncerLapiBypassRules` contains `{host: "^probe\\.example$"}`
- **AND** `req.Host` is `probe.example`
- **THEN** the LAPI leg is skipped

#### Scenario: Host port is stripped
- **WHEN** `bouncerLapiBypassRules` contains `{host: "^example.com$"}`
- **AND** `req.Host` is `example.com:443`
- **THEN** the LAPI leg is skipped

#### Scenario: IPv6 host with port is stripped
- **WHEN** `bouncerLapiBypassRules` contains `{host: "^::1$"}`
- **AND** `req.Host` is `[::1]:443`
- **THEN** the LAPI leg is skipped

#### Scenario: Host and path are AND
- **WHEN** `bouncerLapiBypassRules` contains `{host: "^example.com$", path: "^/healthz$"}`
- **AND** `req.Host` is `example.com` and `req.URL.Path` is `/other`
- **THEN** the LAPI leg is not skipped for that rule

#### Scenario: Non-matching host does not skip
- **WHEN** `bouncerLapiBypassRules` contains `{host: "^probe\\.example$"}`
- **AND** `req.Host` is `other.example`
- **THEN** the LAPI leg is not skipped for that rule

#### Scenario: Method-only rule matches that method
- **WHEN** `bouncerLapiBypassRules` contains `{method: "^OPTIONS$"}`
- **AND** `req.Method` is `OPTIONS`
- **THEN** the LAPI leg is skipped

#### Scenario: Method is case-sensitive unless the operator writes (?i)
- **WHEN** `bouncerLapiBypassRules` contains `{method: "^post$"}`
- **AND** `req.Method` is `POST`
- **THEN** the LAPI leg is not skipped for that rule

#### Scenario: Leading bang negates the method
- **WHEN** `bouncerLapiBypassRules` contains `{method: "!POST"}`
- **AND** `req.Method` is `GET`
- **THEN** the LAPI leg is skipped

#### Scenario: Header empty pattern means present
- **WHEN** `bouncerLapiBypassRules` contains `{headers: {X-Health: ""}}`
- **AND** the request has header `X-Health` with any value
- **THEN** the LAPI leg is skipped

#### Scenario: Several header names are AND
- **WHEN** `bouncerLapiBypassRules` contains `{headers: {X-Health: "^ok$", X-Role: "^probe$"}}`
- **AND** the request has `X-Health: ok` and no `X-Role`
- **THEN** the LAPI leg is not skipped for that rule

#### Scenario: Cookie names are case-sensitive
- **WHEN** `bouncerLapiBypassRules` contains `{cookies: {session: "^[a-f0-9]+$"}}`
- **AND** the request has cookie `Session` with a hex value and no cookie `session`
- **THEN** the LAPI leg is not skipped for that rule

#### Scenario: First matching rule wins
- **WHEN** `bouncerLapiBypassRules` contains `{path: "^/a"}` then `{path: "^/ab"}`
- **AND** `req.URL.Path` is `/ab`
- **THEN** the LAPI leg is skipped
- **AND** matching stops at the first rule

#### Scenario: Trusted IP still skips the whole plugin
- **WHEN** the client address is in `bouncerClientTrustedIPs`
- **AND** a LAPI bypass rule would match
- **THEN** the request reaches the next handler
- **AND** ServeHTTP does not apply a bypass skip (trusted-IP already skipped both legs)

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
When `bouncerRemediationHeadersCustomName` is non-empty, each remediating response this bouncer writes SHALL set that header to a structured value `kind:reason` or `kind:reason:origin`. `:` is the field separator. Consumers SHALL split at most three fields. There is no space after `:`. Empty header name SHALL still omit the header. Pass, bypass, trusted IP, failure-action passthrough, remap-to-pass, widget-asset passthrough, valid gate-cookie origin GET, disabled bouncer, and startup 503 MUST NOT set this header. The plugin MUST NOT emit `allow: pass`. The plugin MUST NOT add a public config key for this header.

Closed reasons never take a third field. The closed vocabulary is:

| Header | Meaning |
| ------ | ------- |
| `ban:decision-header` | Incoming `bouncerDecisionHeader` is `b` |
| `ban:lapi` | CrowdSec decision type ban, empty metrics origin |
| `ban:lapi:<origin>` | CrowdSec decision type ban; third field is header-safe metrics origin |
| `ban:lapi-failure` | LAPI down / unpublished, fail-closed ban |
| `ban:stream-unhealthy` | Stream miss + unhealthy, fail-closed ban |
| `ban:cache-fail` | Redis/cache fail-closed |
| `ban:unparseable-request` | `GetRemoteIP` failed or client IP would not parse |
| `ban:appsec` | AppSec JSON `action: ban` |
| `ban:appsec-challenge-empty` | AppSec `action: challenge` with empty body (fail-closed to ban page) |
| `ban:appsec-failure` | AppSec down / unusable verdict, fail-closed ban |
| `ban:captcha-downgrade` | Kind was captcha; this router served a ban page (unsubscribed / unpublished / invalid captcha client) |
| `captcha:decision-header` | Incoming `bouncerDecisionHeader` is `c` |
| `captcha:lapi` / `captcha:lapi:<origin>` | CrowdSec decision type captcha (same origin encoding) |
| `captcha:lapi-failure` | LAPI fail-closed captcha |
| `captcha:stream-unhealthy` | Stream fail-closed captcha |
| `captcha:appsec-failure` | AppSec fail-closed captcha |
| `captcha:appsec` | AppSec JSON `action: captcha` (envelope relay, not pkg/captcha) |
| `captcha:challenge` | AppSec bot-detection `action: challenge` with non-empty body |
| `captcha:solved` | 302 after a successful solve (token pass or second-tab captcha-form POST) |
| `error:client-disconnected` | Client gone during AppSec body copy |

LAPI third field SHALL be the usage-metrics origin already returned by `LookupRemediation` / `LiveLookup` (`MetricsOrigin`), after strip of CR/LF/TAB and rewriting only the prefix `lists:` → `lists_`. Empty origin omits the third field. The plugin MUST NOT globally replace remaining colons. The plugin MUST NOT change `MetricsOrigin` or DecisionStore packing. Plugin `OriginPlugin*` constants and AppSec specials are reason tokens, never a third field. Client address stays `pkg/ip.GetRemoteIP` on `clientRequest`; this header MUST NOT reconstruct identity.

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

#### Scenario: Forced ban header is decision-header
- **WHEN** `bouncerRemediationHeadersCustomName` is set
- **AND** `bouncerDecisionHeader` forces `b`
- **THEN** the header value is `ban:decision-header`

#### Scenario: Captcha-downgrade on an unsubscribed router
- **WHEN** `bouncerRemediationHeadersCustomName` is set
- **AND** the remediation kind is captcha
- **AND** this bouncer did not subscribe to captcha
- **THEN** the response is a ban
- **AND** the header value is `ban:captcha-downgrade`

#### Scenario: Unparseable client address
- **WHEN** `bouncerRemediationHeadersCustomName` is set
- **AND** `GetRemoteIP` fails, or the parsed client IP is nil
- **THEN** the header value is `ban:unparseable-request`

#### Scenario: Pass path still omits the header
- **WHEN** `bouncerRemediationHeadersCustomName` is set
- **AND** the request is trusted, bypassed, remapped to pass, or otherwise calls `next` without a remediating writer
- **THEN** that response does not set the remediation header

#### Scenario: Empty name still disables
- **WHEN** `bouncerRemediationHeadersCustomName` is empty
- **AND** the bouncer writes a ban page
- **THEN** no structured remediation header is set
