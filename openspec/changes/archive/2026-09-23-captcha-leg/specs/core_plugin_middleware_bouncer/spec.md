## ADDED Requirements

### Requirement: Captcha verdict without a published client is a ban
When the remediation kind is captcha and the loaded captcha binding is empty or not valid, the bouncer SHALL remediate as a ban. It MUST NOT construct a fallback local captcha client on the request path or in `bouncer.New`. A bounce-only middleware MUST NOT build a captcha client from leftover `bouncerCaptcha*` keys.

#### Scenario: Unpublished captcha with startup block off bans
- **WHEN** the bouncer subscribed to captcha, `bouncerStartupBlock` is false, the loaded captcha value is empty, and the verdict is captcha
- **THEN** the response is a ban
- **AND** no captcha challenge page is served

#### Scenario: Bounce-only leftover keys are not a client
- **WHEN** `captchaEnabled` is false, `bouncerCaptchaProvider` is set on this router, and no captcha client is published
- **THEN** `bouncer.New` does not construct a captcha client from those keys
- **AND** a captcha verdict remediates as a ban when startup block is false

### Requirement: Remediation header is not stored on the shared captcha client
The remediation header name SHALL stay on the Bouncer (`bouncerRemediationHeadersCustomName`). Challenge page, solved redirect, and captcha-kind responses SHALL write this router's header. The published `captcha.Client` MUST NOT store a remediation header copied from the owner.

#### Scenario: Subscriber uses its own header name
- **WHEN** the owner sets `bouncerRemediationHeadersCustomName` to `X-Owner` and a subscriber of that captcha name sets `X-Route`
- **AND** the subscriber serves a captcha challenge
- **THEN** the response header name is `X-Route`
- **AND** it is not `X-Owner`

## MODIFIED Requirements

### Requirement: Bouncer binds clients through atomic late bind
The per-router bouncer SHALL hold three optional bound clients as `atomic.Value` fields (LAPI, AppSec, and captcha), each able to hold a typed nil. `ServeHTTP` SHALL `Load` those fields only and MUST NOT resolve instance names, Peek slot tables, or Open clients on the request path. Subscribers MUST NOT Bind reclaim on those clients. The bouncer SHALL read `lapiMode` from the loaded LAPI client on each request, not from a copy taken at `New`. When `bouncerEnabled` is false the handler SHALL call `next` without applying decisions while owners may still Open and publish.

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

### Requirement: Captcha siteverify Timeout is the effective captcha seconds
When an owning middleware constructs the captcha provider `http.Client`, that client’s `Timeout` SHALL be `config.BouncerCaptchaSiteverifyHTTPTimeoutSeconds` seconds. It MUST NOT read a shared or inherited timeout. Subscribers SHALL use the published client and MUST NOT construct a second siteverify client from leftover keys. `pkg/captcha` SHALL keep local parameter names (`siteKey`, `secretKey`, `gateSecret`); the owner SHALL pass `BouncerCaptchaSiteKey` into those arguments and MUST NOT grow a `bouncer` field on captcha.

#### Scenario: Captcha knob sets siteverify Timeout
- **WHEN** a captcha owner Opens with a captcha provider set and `BouncerCaptchaSiteverifyHTTPTimeoutSeconds` 1
- **THEN** the stored captcha siteverify `http.Client` Timeout is 1 second

#### Scenario: Captcha omit uses the captcha default
- **WHEN** a captcha owner Opens with a captcha provider set and the captcha timeout omitted
- **THEN** the stored captcha siteverify `http.Client` Timeout is 10 seconds

#### Scenario: Two subscribers share one siteverify client
- **WHEN** two bouncing middlewares subscribe to the same published captcha instance
- **THEN** both use that instance's siteverify `http.Client`
- **AND** neither constructs a local captcha client

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
