## MODIFIED Requirements

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
A missing subscribed LAPI client SHALL use this router's LAPI failure action. A missing subscribed AppSec client SHALL use this router's AppSec failure action when the request reaches AppSec. A missing subscribed captcha client SHALL ban a captcha verdict. A missing subscribed ModSec client SHALL use this router's `bouncerModsecFailureAction` when the request reaches ModSec. A missing subscribed rate-limit client SHALL charge no bucket and the request SHALL continue to the AppSec step; the router has no rate-limit failure action of its own, because the policy is the owner's. `New` MUST NOT wait for a client to be published. A leg the bouncer did not subscribe to is not part of that check.

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
| `captcha:appsec` | Router captcha page for an AppSec JSON `action: captcha`, or for a challenge-marker POST that AppSec let through |
| `captcha:challenge` | AppSec bot-detection `action: challenge` with non-empty body |
| `captcha:solved` | 302 after a successful solve (token pass or second-tab captcha-form POST) |
| `error:client-disconnected` | Client gone during an AppSec or ModSec body copy |
| `error:client-body-read` | Client body could not be read whole during an AppSec or ModSec body copy (HTTP 400) |

LAPI third field SHALL be the usage-metrics origin already returned by `LookupRemediation` / `LiveLookup` (`MetricsOrigin`), after strip of CR/LF/TAB and rewriting only the prefix `lists:` → `lists_`. Empty origin omits the third field. The plugin MUST NOT globally replace remaining colons. The plugin MUST NOT change `MetricsOrigin` or DecisionStore packing. Plugin origins, including `plugin:rules:<name>`, and AppSec specials are reason tokens, never a third field. A metrics origin that starts with `plugin:rules:` SHALL map to closed reason `rules` (no third field). A metrics origin that starts with `plugin:ratelimit:` SHALL map to reason `ratelimit` with the rest of the origin (the bucket name) as the third field, after the same CR/LF/TAB strip. Bucket names cannot contain `:`, so the value still splits into at most three fields. Origin `plugin:ratelimit_failure` SHALL map to closed reason `ratelimit-failure` (no third field). Client address stays `pkg/ip.GetRemoteIP` on `clientRequest`; this header MUST NOT reconstruct identity.

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
- a captcha challenge-form POST that AppSec let through.

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
