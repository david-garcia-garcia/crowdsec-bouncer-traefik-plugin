## ADDED Requirements

### Requirement: Body read deadline on a WAF leg is a 400, not a ban
When AppSec `Query` or ModSec `Inspect` returns `ErrBodyReadTimeout`, the bouncer SHALL answer HTTP 400 `Bad Request` and MUST NOT call `next`, whatever that leg's failure action says. It SHALL NOT write a ban template or `bouncerRemediationStatusCode`, SHALL NOT count a dropped request, and SHALL NOT record the leg's gate. With `bouncerRemediationHeadersCustomName` set, the header SHALL be `error:body-read-timeout` (no third field).

#### Scenario: Passthrough does not let a stalled AppSec body through
- **WHEN** `bouncerAppsecFailureAction` is `passthrough`
- **AND** a POST without `Content-Length` does not arrive within `appsecBodyReadTimeoutSeconds`
- **THEN** the response is HTTP 400
- **AND** origin is not called
- **AND** no dropped request is counted

#### Scenario: The deadline is not a ban on either leg
- **WHEN** the AppSec or ModSec body read deadline expires
- **AND** that leg's failure action is `ban` or `captcha`
- **THEN** the response is HTTP 400, not the ban template and not a captcha page
- **AND** if `bouncerRemediationHeadersCustomName` is `X-Remediation` the response header value is `error:body-read-timeout`

#### Scenario: A bypass rule skips the read
- **WHEN** a matching action rule carries `bypassAppsec` (or `bypassModsec` for ModSec)
- **AND** the request body has no `Content-Length` and never ends
- **THEN** that leg does not read the body and starts no deadline

### Requirement: Body read deadline is logged at WARN once per window per leg
On `ErrBodyReadTimeout` the bouncer SHALL log WARN through `logger.Debounced` with a 5 second window, keyed by the message text, so each leg logs at most one line per window. AppSec SHALL use `AppSec request body not received within appsecBodyReadTimeoutSeconds; request blocked. Exclude streaming routes with a bouncerActionRules bypassAppsec (or bypass) rule`. ModSec SHALL use the same text with `ModSec`, `modsecBodyReadTimeoutSeconds`, and `bypassModsec`.

#### Scenario: Two timeouts in one window log once
- **WHEN** two AppSec body reads hit the deadline within 5 seconds
- **THEN** one WARN line with the AppSec message is logged
- **AND** both requests are answered HTTP 400

#### Scenario: The WARN names the request without the query string
- **WHEN** the AppSec body read deadline expires for `POST https://example.com/upload?token=secret`
- **THEN** the WARN carries attrs `ip` (the client address chosen by `pkg/ip.GetRemoteIP`), `method`, `host`, `path` `/upload`, and `timeoutSeconds`
- **AND** it does not contain `secret`

## MODIFIED Requirements

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
| `error:body-read-timeout` | A body of unknown length did not arrive within the leg's `appsecBodyReadTimeoutSeconds` or `modsecBodyReadTimeoutSeconds` (HTTP 400), whatever the leg's failure action |

LAPI third field SHALL be the usage-metrics origin already returned by `LookupRemediation` / `LiveLookup` (`MetricsOrigin`), after strip of CR/LF/TAB and rewriting only the prefix `lists:` → `lists_`. Empty origin omits the third field. The plugin MUST NOT globally replace remaining colons. The plugin MUST NOT change `MetricsOrigin` or DecisionStore packing. Plugin origins, including `plugin:rules:<name>`, and AppSec specials are reason tokens, never a third field. A metrics origin that starts with `plugin:rules:` SHALL map to closed reason `rules` (no third field). A metrics origin that starts with `plugin:ratelimit:` SHALL map to reason `ratelimit` with the rest of the origin (the bucket name) as the third field, after the same CR/LF/TAB strip. Bucket names cannot contain `:`, so the value still splits into at most three fields. Origin `plugin:ratelimit_failure` SHALL map to closed reason `ratelimit-failure` (no third field). Origin `plugin:ratelimit` (no bucket) SHALL map to reason `ratelimit` with no third field. Client address stays `pkg/ip.GetRemoteIP` on `clientRequest`; this header MUST NOT reconstruct identity.

The bouncer SHALL format ban, AppSec relay, disconnect, client-body, captcha-downgrade, and captcha challenge-page values. `pkg/captcha` MUST NOT own the closed table. Challenge page SHALL receive the already-formatted value. Pass 302 and Check-true form POST SHALL write `captcha:solved` with no third field.

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

#### Scenario: Body read timeout header
- **WHEN** `bouncerRemediationHeadersCustomName` is `X-Remediation`
- **AND** a WAF leg's body read deadline expires
- **THEN** the response header `X-Remediation` is `error:body-read-timeout`
