## ADDED Requirements

### Requirement: The rate limit runs between the LAPI step and the AppSec step
When `rateLimitEnabled` is true, ServeHTTP SHALL run the rate-limit step after the LAPI step and before the AppSec step. Requests that never reach it SHALL NOT be charged to any bucket: a `GetRemoteIP` error, a trusted client, a disabled bouncer, a matching action-rule `ban`, and a request the LAPI step answered (a CrowdSec ban, an unsolved CrowdSec captcha, a LAPI fail-closed ban or captcha). A request the LAPI step let through (no decision, a valid captcha gate cookie, a LAPI skip, failure action `passthrough`) SHALL reach the rate-limit step. The action-rule captcha gate and the AppSec query SHALL run after the rate-limit step, so a denied request never reaches AppSec. When `rateLimitEnabled` is false, the request path SHALL be unchanged.

The rate-limit step SHALL NOT increment `processed` a second time.

#### Scenario: LAPI ban is not charged
- **WHEN** CrowdSec has a ban for the client
- **AND** a catch-all bucket allows 1 request per minute
- **THEN** every request of that client gets the LAPI ban page
- **AND** the bucket counter for that client does not move

#### Scenario: Denied request does not reach AppSec
- **WHEN** a `deny` bucket is over its limit for the client
- **AND** AppSec is enabled on the router
- **THEN** the response is the rate-limit deny
- **AND** AppSec is not queried

#### Scenario: Trusted client is not charged
- **WHEN** the client address is in `bouncerClientTrustedIps`
- **THEN** the request reaches the backend and no bucket counter moves

#### Scenario: Action-rule captcha comes after the rate limit
- **WHEN** a `captcha` action rule matches the request and a `deny` bucket is over its limit for the client
- **THEN** the response is the rate-limit deny, not the captcha page
- **AND** WARN `warnCaptchaSuperseded` is logged with attribute `name` of that captcha rule

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
| `ban:ratelimit:<bucket>` | A rate-limit bucket with `action: deny` is over its limit; third field is the bucket name |
| `ban:ratelimit-failure` | Rate-limit counter could not answer, failure action `ban` |
| `ban:captcha-downgrade` | Kind was captcha; this router served a ban page (unsubscribed / unpublished / invalid captcha client) |
| `captcha:rules` | Matching action rule applied captcha |
| `captcha:lapi` / `captcha:lapi:<origin>` | CrowdSec decision type captcha (same origin encoding) |
| `captcha:lapi-failure` | LAPI fail-closed captcha |
| `captcha:stream-unhealthy` | Stream fail-closed captcha |
| `captcha:appsec-failure` | AppSec fail-closed captcha |
| `captcha:ratelimit-failure` | Rate-limit counter could not answer, failure action `captcha` |
| `captcha:appsec` | Router captcha page for an AppSec JSON `action: captcha`, or for a challenge-marker POST that AppSec let through |
| `captcha:challenge` | AppSec bot-detection `action: challenge` with non-empty body |
| `captcha:solved` | 302 after a successful solve (token pass or second-tab captcha-form POST) |
| `error:client-disconnected` | Client gone during AppSec body copy |
| `error:client-body-read` | Client body could not be read whole during AppSec body copy (HTTP 400) |

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

#### Scenario: Rate-limit deny carries the bucket name
- **WHEN** `bouncerRemediationHeadersCustomName` is set
- **AND** bucket `login` with `action: deny` is over its limit
- **THEN** the header value is `ban:ratelimit:login`

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

`name` SHALL be required, unique in the list, and MUST NOT contain `:`. `action` SHALL be a required non-empty array of tokens `bypass`, `bypassLapi`, `bypassAppsec`, `bypassCaptcha`, `bypassRateLimit`, `ban`, `captcha`. Order in the array SHALL NOT matter. `bypass` SHALL skip both LAPI and AppSec. `bypass` SHALL NOT skip the rate limit. Duplicates, unknown tokens, an empty array, or an omitted action SHALL fail `New`. `ban` MUST be the only token in that array; `ban` combined with `captcha` or any skip SHALL fail `New`. `captcha` combined with `bypassCaptcha` in one array SHALL fail `New`. The action array is not a match predicate.

All matching rows SHALL contribute. This is not first-match-wins. List order SHALL pick the origin name only when two rows share the same winning remediation (first matching `ban`, else first matching `captcha`).

After a `GetRemoteIP` error (HTTP 502, not a ban), `IncProcessed`, and the trusted-IP skip, ServeHTTP SHALL collect every matching row. Trusted clients MUST NOT hit these rules. A `GetRemoteIP` error MUST NOT be saved by a matching skip.

- Any matching `ban` SHALL remediate immediately as ban. LAPI, the rate limit, and AppSec MUST NOT run. Metrics origin SHALL be `plugin:rules:<name>` where `<name>` is the first matching ban row. `remediation=ban`. A skip on another matching row MUST NOT weaken this ban. Closed remediation-header reason SHALL be `rules` (no third field) when that header is configured.
- Else fold every match: `bypass` or `bypassLapi` SHALL skip LAPI; `bypass` or `bypassAppsec` SHALL skip AppSec; `bypassRateLimit` SHALL skip the rate limit; any `captcha` token SHALL set a captcha flag. Skips SHALL add; they MUST NOT cancel each other or a captcha flag. Any `bypassCaptcha` token SHALL set a captcha-bypass flag, and that flag SHALL clear the captcha flag (requirement "bypassCaptcha lets a request through where a captcha would be served"). `bypassCaptcha` skips no leg. Two exceptions drop a skip: a row with a `path` predicate skips nothing (LAPI, AppSec, or the rate limit) on a path with more than one reading (requirement "Action-rule skips need a single-reading path"), and no row skips AppSec under `/crowdsec-internal/challenge/` (`core_plugin_appsec_bot-detection`, "Action rules cannot skip AppSec on the challenge prefix").
- A LAPI skip SHALL skip `LookupRemediation`, `LiveLookup`, missing-subscribed-LAPI failure action, and stream/alone unhealthy failure action.
- An AppSec skip SHALL skip AppSec `Query` and the AppSec body buffer on that path.
- A rate-limit skip SHALL skip every bucket: no bucket is charged, none can deny, and the rate-limit failure action does not apply.
- `captcha` MUST NOT return immediately. Legs that were not skipped SHALL still run. An active LAPI ban, or a fail-closed ban from that leg (lookup error, stream/alone unhealthy, failure action `ban`), SHALL prevail over the captcha rule and SHALL keep that leg's origin, not `plugin:rules:`. An AppSec `ban` verdict, or an AppSec failure-action `ban`, SHALL prevail over the captcha rule and SHALL keep origin `appsec` / `plugin:appsec_failure`. Those drops SHALL log WARN `warnCaptchaSuperseded` with attributes `name` (the first matching captcha row that lost) and dest `ip`. The plugin MUST NOT log attr `header` for this WARN.
- An AppSec `challenge` with non-empty body is not a ban and MUST NOT override the captcha rule (MUST NOT relay; apply the plugin gate). An AppSec `challenge` with empty `UserBodyContent` SHALL stay dest fail-closed ban (`ban:appsec-challenge-empty`, origin `appsec`) and therefore SHALL prevail over the captcha rule like `ban`. Empty-challenge dest when no captcha rule matched MUST NOT change.
- A CrowdSec captcha decision SHALL be unchanged: the rule MUST NOT replace that outcome, the metrics origin SHALL stay the CrowdSec origin, and AppSec for that decision SHALL stay after a valid captcha gate cookie, not before the challenge page.
- If no leg banned and a captcha rule matched, ServeHTTP SHALL serve the existing captcha gate. Origin `plugin:rules:<name>` of the first matching captcha row, `remediation=captcha`, only when that rule is what is applied. A valid gate cookie SHALL still pass. After the cookie is valid, AppSec SHALL still run unless a matching `bypass` or `bypassAppsec` skipped it.
- When a captcha rule matched and AppSec was not skipped, AppSec Query SHALL run before serving the plugin captcha gate so an AppSec ban can stop an unsolved visitor.
- The only way for a captcha rule to avoid a LAPI ban is a matching `bypass` or `bypassLapi` (same row or another matching row). The only way to avoid an AppSec ban is a matching `bypass` or `bypassAppsec`.
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
- **AND** ServeHTTP does not consult LAPI or AppSec

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
