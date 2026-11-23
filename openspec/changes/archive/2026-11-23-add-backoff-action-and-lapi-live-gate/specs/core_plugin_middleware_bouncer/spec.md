## MODIFIED Requirements

### Requirement: Structured remediation header values

When `bouncerRemediationHeadersCustomName` is non-empty, each remediating response this bouncer writes SHALL set that header to a structured value `kind:reason` or `kind:reason:origin`. `:` is the field separator. Consumers SHALL split at most three fields. There is no space after `:`. Empty header name SHALL still omit the header. Pass, skip-to-next from action rules, trusted IP, failure-action passthrough, backoff-action passthrough, remap-to-pass, widget-asset passthrough, valid gate-cookie origin GET, disabled bouncer, and startup 503 MUST NOT set this header. The plugin MUST NOT emit `allow: pass`. The plugin MUST NOT add a public config key for this header.

Closed reasons never take a third field, except `lapi` (the metrics origin) and `ratelimit` (the bucket name). The closed vocabulary is:

| Header | Meaning |
| ------ | ------- |
| `ban:rules` | Matching action rule applied ban |
| `ban:lapi` | CrowdSec decision type ban, empty metrics origin |
| `ban:lapi:<origin>` | CrowdSec decision type ban; third field is header-safe metrics origin |
| `ban:lapi-failure` | LAPI down / unpublished, fail-closed ban |
| `ban:lapi-backoff` | LAPI live/none gate backing off, backoff action `ban` (no GET sent) |
| `ban:stream-unhealthy` | Stream miss + unhealthy, fail-closed ban |
| `ban:cache-fail` | Redis/cache fail-closed |
| `ban:appsec` | AppSec JSON `action: ban` |
| `ban:appsec-challenge-empty` | AppSec `action: challenge` with empty body (fail-closed to ban page) |
| `ban:appsec-action-empty` | AppSec action other than `allow` / `ban` / `captcha` / `challenge` with empty body (fail-closed to ban page) |
| `ban:appsec-failure` | AppSec down / unusable verdict, fail-closed ban |
| `ban:appsec-backoff` | AppSec gate backing off, backoff action `ban` (AppSec not called) |
| `ban:modsec` | CRS sidecar copied 3xx/4xx block |
| `ban:modsec-failure` | ModSec sidecar down / unpublished, failure action `ban` (RemediationReason `MODSEC`) |
| `ban:modsec-backoff` | ModSec gate backing off, backoff action `ban` (sidecar not called; RemediationReason `MODSEC`) |
| `ban:ratelimit:<bucket>` | A rate-limit bucket with `action: ratelimit` answered, or a `captcha` bucket answered as `ratelimit` (`bypassCaptcha`, or no usable captcha); third field is the bucket name |
| `ban:ratelimit-failure` | Rate-limit counter could not answer, failure action `ban` |
| `ban:captcha-downgrade` | Kind was captcha; this router served a ban page (unsubscribed / unpublished / invalid captcha client) |
| `captcha:rules` | Matching action rule applied captcha |
| `captcha:lapi` / `captcha:lapi:<origin>` | CrowdSec decision type captcha (same origin encoding) |
| `captcha:lapi-failure` | LAPI fail-closed captcha |
| `captcha:lapi-backoff` | LAPI live/none gate backing off, backoff action `captcha` |
| `captcha:stream-unhealthy` | Stream fail-closed captcha |
| `captcha:appsec-failure` | AppSec fail-closed captcha |
| `captcha:appsec-backoff` | AppSec gate backing off, backoff action `captcha` |
| `captcha:modsec-failure` | ModSec sidecar down / unpublished, failure action `captcha` |
| `captcha:modsec-backoff` | ModSec gate backing off, backoff action `captcha` |
| `captcha:ratelimit:<bucket>` | Router captcha page for a rate-limit bucket with `action: captcha`; third field is the bucket name |
| `captcha:ratelimit-failure` | Rate-limit counter could not answer, failure action `captcha` |
| `captcha:ratelimit` | Router captcha page for a challenge-marker POST that the rate-limit leg's captcha gate answered with the challenge again (no bucket answered) |
| `captcha:appsec` | Router captcha page for an AppSec JSON `action: captcha`, or for a challenge-marker POST that AppSec let through |
| `captcha:challenge` | AppSec bot-detection `action: challenge` with non-empty body |
| `captcha:solved` | 302 after a successful solve (token pass or second-tab captcha-form POST) |
| `error:client-disconnected` | Client gone during an AppSec or ModSec body copy |
| `error:client-body-read` | Client body could not be read whole during an AppSec or ModSec body copy (HTTP 400) |

LAPI third field SHALL be the usage-metrics origin already returned by `LookupRemediation` / `LiveLookup` (`MetricsOrigin`), after strip of CR/LF/TAB and rewriting only the prefix `lists:` → `lists_`. Empty origin omits the third field. The plugin MUST NOT globally replace remaining colons. The plugin MUST NOT change `MetricsOrigin` or DecisionStore packing. Plugin origins, including `plugin:rules:<name>`, and AppSec specials are reason tokens, never a third field. A metrics origin that starts with `plugin:rules:` SHALL map to closed reason `rules` (no third field). A metrics origin that starts with `plugin:ratelimit:` SHALL map to reason `ratelimit` with the rest of the origin (the bucket name) as the third field, after the same CR/LF/TAB strip. Bucket names cannot contain `:`, so the value still splits into at most three fields. Origin `plugin:ratelimit_failure` SHALL map to closed reason `ratelimit-failure` (no third field). Origin `plugin:ratelimit` (no bucket) SHALL map to reason `ratelimit` with no third field. A `*-backoff` reason SHALL be passed to the writer by the leg that answered the gate skip, never derived from the metrics origin: a backoff answer shares its leg's failure origin (`plugin:lapi_failure`, `plugin:appsec_failure`, `plugin:modsec_failure`), and that origin SHALL keep mapping to `<leg>-failure`. Client address stays `pkg/ip.GetRemoteIP` on `clientRequest`; this header MUST NOT reconstruct identity.

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

#### Scenario: Backoff ban is labelled per leg
- **WHEN** `bouncerRemediationHeadersCustomName` is set
- **AND** the LAPI, AppSec, or ModSec gate is backing off and that leg's backoff action is `ban`
- **THEN** the header value is `ban:lapi-backoff`, `ban:appsec-backoff`, or `ban:modsec-backoff`
- **AND** the usage-metrics origin is that leg's failure origin

#### Scenario: Backoff captcha is labelled per leg
- **WHEN** `bouncerRemediationHeadersCustomName` is set
- **AND** the AppSec gate is backing off, `bouncerAppsecBackOffAction` is `captcha`, and the router serves its captcha page
- **THEN** the header value is `captcha:appsec-backoff`

#### Scenario: Backoff passthrough sets no header
- **WHEN** `bouncerRemediationHeadersCustomName` is set
- **AND** a gate is backing off and that leg's backoff action is `passthrough`
- **THEN** the response from the backend does not carry the remediation header

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

### Requirement: bypassCaptcha lets a request through where a captcha would be served
`bouncerActionRules` SHALL accept the action token `bypassCaptcha`. It is for requests that cannot solve a captcha, such as machine-to-machine API calls. When at least one matching row carries it, ServeHTTP MUST NOT serve this router's captcha gate for that request: wherever the gate would have written a challenge, a solved-form redirect, or a captcha downgrade ban, nothing is written and the request continues to the next leg, then to `next`. `ActionMatch.BypassCaptchaName` SHALL name the first matching row with the token; empty SHALL mean none.

`bypassCaptcha` skips no leg. The LAPI lookup and the AppSec `Query` SHALL still run, so a ban still bans.

The captcha sources that continue instead of writing SHALL be:

- a LAPI decision whose applied kind is captcha (cache lookup and live lookup);
- the LAPI failure action `captcha` (missing subscribed client, live lookup error, unhealthy stream);
- the LAPI backoff action `captcha` (live/none gate skip);
- an AppSec `captcha` verdict;
- the AppSec failure action `captcha` (missing client, or a query failure);
- the AppSec backoff action `captcha` (gate skip);
- the ModSec failure action `captcha` (missing client, or no sidecar verdict);
- the ModSec backoff action `captcha` (gate skip);
- the rate-limit failure action `captcha` (counter error);
- a captcha challenge-form POST that AppSec let through;
- a captcha challenge-form POST that the rate-limit step hands to the captcha gate.

A bypassed captcha MUST NOT increment `dropped`, MUST NOT set the remediation header, and MUST NOT log WARN `crowdsec bouncer captcha unsubscribed`. It SHALL log TRACE `bypassCaptcha` with attrs `ip` and `name` (the rule). The bypass SHALL apply before the captcha downgrade: on a router with no usable captcha client the request also continues, it is not banned.

When a captcha-bypass flag is set, `ActionMatch.CaptchaName` SHALL be empty even when another matching row carries `captcha`. No captcha rule applies to that request, and WARN `warnCaptchaSuperseded` MUST NOT be logged for it.

A rate-limit bucket with `action: captcha` is the one exception: on a request a `bypassCaptcha` row matches, that bucket SHALL answer as a `ratelimit` bucket (`rateLimitStatusCode`, `Retry-After`, `ban:ratelimit:<bucket>`) instead of letting the request through, so a rate limit does not become unlimited (`core_plugin_ratelimit_buckets`).

Everything that is not this router's captcha gate SHALL be unchanged: a `ban` row; a LAPI ban; a fail-closed ban from the LAPI leg (failure action or backoff action `ban`); an AppSec `ban` verdict, failure-action `ban`, or backoff-action `ban`; a ModSec failure-action or backoff-action `ban`; an AppSec `challenge` (relayed when it carries a page, `ban:appsec-challenge-empty` when it does not, although its header value starts with `captcha:`); and any other AppSec action.

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

#### Scenario: Backoff action captcha continues
- **WHEN** the same rule matches, the LAPI gate is backing off, and `bouncerLapiBackOffAction` is `captcha`
- **THEN** no captcha page is written
- **AND** the AppSec leg runs, then `next`

#### Scenario: Backoff action ban still bans
- **WHEN** the same rule matches, the LAPI gate is backing off, and `bouncerLapiBackOffAction` is `ban`
- **THEN** ServeHTTP remediates as ban with `ban:lapi-backoff`

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


## ADDED Requirements

### Requirement: A gate skip answers with that leg's backoff action
When the LAPI, AppSec, or ModSec Client reports a gate skip, the router SHALL apply its own `bouncer<Leg>BackOffAction`, resolved in `bouncer.New` like the failure action. `ban` SHALL write the ban template with that leg's RemediationReason. `captcha` SHALL serve the router's captcha gate; with no usable captcha client it SHALL ban (`ban:captcha-downgrade`). The failure action MUST NOT apply to a skip.

#### Scenario: Two routers on one gate answer differently
- **WHEN** two routers subscribe to the same AppSec instance and its gate is backing off
- **AND** one router sets `bouncerAppsecBackOffAction: ban` and the other omits it
- **THEN** the first router answers `ban:appsec-backoff`
- **AND** the second router passes the request on

#### Scenario: Captcha backoff without a usable captcha bans
- **WHEN** the ModSec gate is backing off and `bouncerModsecBackOffAction` is `captcha`
- **AND** the router's captcha instance is not published
- **THEN** the response is a ban with `ban:captcha-downgrade`

### Requirement: A backoff ban outranks a captcha action rule
A backoff-action `ban` on any leg SHALL prevail over a matching `captcha` action rule, as that leg's failure-action `ban` does. It SHALL keep that leg's failure origin, not `plugin:rules:`, and SHALL log WARN `warnCaptchaSuperseded` with attrs `name` and `ip`.

#### Scenario: LAPI backoff ban beats a captcha rule
- **WHEN** a matching row is `{name: gate, action: [captcha]}`
- **AND** the LAPI gate is backing off and `bouncerLapiBackOffAction` is `ban`
- **THEN** the response is a ban with `ban:lapi-backoff` and origin `plugin:lapi_failure`
- **AND** WARN `warnCaptchaSuperseded` is logged with `name` `gate`

### Requirement: A backoff action stricter than the failure action warns at startup
`bouncer.New` SHALL log one WARN `crowdsec bouncer backoff action stricter than failure action` per subscribed leg (LAPI, AppSec, ModSec) when that leg's effective backoff action ranks above its effective failure action (passthrough < captcha < ban). Attrs SHALL be `leg`, `failureAction`, `backOffAction`. It MUST NOT fail `New`. A router that opens LAPI itself in `stream` or `alone` SHALL NOT warn for LAPI.

#### Scenario: LAPI passthrough with the default backoff ban warns
- **WHEN** a router subscribes to a LAPI instance, sets `bouncerLapiFailureAction: passthrough`, and omits `bouncerLapiBackOffAction`
- **THEN** `New` succeeds
- **AND** one WARN names `leg` `lapi`, `failureAction` `passthrough`, `backOffAction` `ban`

#### Scenario: Defaults do not warn
- **WHEN** a router subscribes to LAPI, AppSec, and ModSec and sets no failure or backoff action
- **THEN** no stricter-than WARN is logged

#### Scenario: Stream owner does not warn for LAPI
- **WHEN** a router opens LAPI in `stream` mode with `bouncerLapiFailureAction: passthrough`
- **THEN** no stricter-than WARN is logged for LAPI

#### Scenario: Unsubscribed leg does not warn
- **WHEN** a router does not subscribe to ModSec and sets `bouncerModsecBackOffAction: ban`
- **THEN** no stricter-than WARN is logged for ModSec
