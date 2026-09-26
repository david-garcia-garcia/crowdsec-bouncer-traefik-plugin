## ADDED Requirements

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

## MODIFIED Requirements

### Requirement: Client disconnect during AppSec body buffer is not a ban
When AppSec `Query` returns `ErrClientDisconnected`, the bouncer SHALL stop without calling origin, SHALL NOT write a ban template or `BouncerRemediationStatusCode`, and SHALL NOT increment LAPI dropped-request metrics. It SHALL log the disconnect at TRACE only. When `bouncerRemediationHeadersCustomName` is set, it SHALL set that response header to `error:client-disconnected` (kind `error`, reason `client-disconnected`; no third field) and MUST NOT call `WriteHeader`. `bouncerAppsecFailureAction` SHALL NOT change this path.

#### Scenario: Canceled upload is not a CrowdSec 403
- **WHEN** AppSec is enabled and the client disconnects while the readable body is buffered
- **THEN** origin is not called
- **AND** the response is not a ban
- **AND** if `bouncerRemediationHeadersCustomName` is `X-Remediation` the response header value is `error:client-disconnected`

### Requirement: Remediation header is not stored on the shared captcha client
The remediation header name SHALL stay on the Bouncer (`bouncerRemediationHeadersCustomName`). Challenge page, solved redirect, and captcha-kind responses SHALL write this router's header. The published `captcha.Client` MUST NOT store a remediation header copied from the owner. The bouncer SHALL pass the already-formatted challenge-page value into `ServeHTTP`. Pass 302 and Check-true form POST SHALL write `captcha:solved` inside captcha. Captcha MUST NOT import plugin origins or the closed reason table.

#### Scenario: Subscriber uses its own header name
- **WHEN** the owner sets `bouncerRemediationHeadersCustomName` to `X-Owner` and a subscriber of that captcha name sets `X-Route`
- **AND** the subscriber serves a captcha challenge
- **THEN** the response header name is `X-Route`
- **AND** it is not `X-Owner`
