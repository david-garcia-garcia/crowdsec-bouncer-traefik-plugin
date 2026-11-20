## ADDED Requirements

### Requirement: bypassCaptcha lets a request through where a captcha would be served
`bouncerActionRules` SHALL accept the action token `bypassCaptcha`. It is for requests that cannot solve a captcha, such as machine-to-machine API calls. When at least one matching row carries it, ServeHTTP MUST NOT serve this router's captcha gate for that request: wherever the gate would have written a challenge, a solved-form redirect, or a captcha downgrade ban, nothing is written and the request continues to the next leg, then to `next`. `ActionMatch.BypassCaptchaName` SHALL name the first matching row with the token; empty SHALL mean none.

`bypassCaptcha` skips no leg. The LAPI lookup and the AppSec `Query` SHALL still run, so a ban still bans.

The captcha sources that continue instead of writing SHALL be:

- a LAPI decision whose applied kind is captcha (cache lookup and live lookup);
- the LAPI failure action `captcha` (missing subscribed client, live lookup error, unhealthy stream);
- an AppSec `captcha` verdict;
- the AppSec failure action `captcha` (missing client, or a query failure);
- a captcha challenge-form POST that AppSec let through.

A bypassed captcha MUST NOT increment `dropped`, MUST NOT set the remediation header, and MUST NOT log WARN `crowdsec bouncer captcha unsubscribed`. It SHALL log TRACE `bypassCaptcha` with attrs `ip` and `name` (the rule). The bypass SHALL apply before the captcha downgrade: on a router with no usable captcha client the request also continues, it is not banned.

When a captcha-bypass flag is set, `ActionMatch.CaptchaName` SHALL be empty even when another matching row carries `captcha`. No captcha rule applies to that request, and WARN `warnCaptchaSuperseded` MUST NOT be logged for it.

Everything that is not this router's captcha gate SHALL be unchanged: a `ban` row; a LAPI ban; a fail-closed ban from the LAPI leg; an AppSec `ban` verdict or failure-action `ban`; an AppSec `challenge` (relayed when it carries a page, `ban:appsec-challenge-empty` when it does not, although its header value starts with `captcha:`); and any other AppSec action.

A row with a `path` predicate SHALL apply `bypassCaptcha` on every request its regex matches. The single-reading path requirement ("Action-rule skips need a single-reading path") covers `bypass`, `bypassLapi`, and `bypassAppsec` only. On a path with more than one reading, a row `{action: [bypassCaptcha, bypassLapi]}` SHALL still bypass the captcha and SHALL NOT skip LAPI. The operator relies on Traefik for the path: Traefik resolves `.` and `..` segments and decodes `%2e` before the plugin runs, and by default does not reject `%2F`, `%5C`, `%3B`, or double encoding (`knowledge/research/ext_traefik_entrypoints_request-path/`).

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

## MODIFIED Requirements

### Requirement: Action rules fold every matching row
The bouncer SHALL expose one public Config list `bouncerActionRules`. Default empty (omit or empty list) SHALL match nothing (setting off). Each row SHALL have `name`, `action`, and the same request predicates as dest `httprule.Rule` (`method`, `path`, `host`, `headers`, `cookies`). An omitted predicate, or `path` / `host` / `method` empty after trim, or an empty `headers` / `cookies` map, SHALL mean any for that predicate. Set predicates on one row SHALL all match (AND).

`name` SHALL be required, unique in the list, and MUST NOT contain `:`. `action` SHALL be a required non-empty array of tokens `bypass`, `bypassLapi`, `bypassAppsec`, `bypassCaptcha`, `ban`, `captcha`. Order in the array SHALL NOT matter. `bypass` SHALL skip both LAPI and AppSec. Duplicates, unknown tokens, an empty array, or an omitted action SHALL fail `New`. `ban` MUST be the only token in that array; `ban` combined with `captcha` or any skip SHALL fail `New`. `captcha` combined with `bypassCaptcha` in one array SHALL fail `New`. The action array is not a match predicate.

All matching rows SHALL contribute. This is not first-match-wins. List order SHALL pick the origin name only when two rows share the same winning remediation (first matching `ban`, else first matching `captcha`).

After a `GetRemoteIP` error (HTTP 502, not a ban), `IncProcessed`, and the trusted-IP skip, ServeHTTP SHALL collect every matching row. Trusted clients MUST NOT hit these rules. A `GetRemoteIP` error MUST NOT be saved by a matching skip.

- Any matching `ban` SHALL remediate immediately as ban. LAPI and AppSec MUST NOT run. Metrics origin SHALL be `plugin:rules:<name>` where `<name>` is the first matching ban row. `remediation=ban`. A skip on another matching row MUST NOT weaken this ban. Closed remediation-header reason SHALL be `rules` (no third field) when that header is configured.
- Else fold every match: `bypass` or `bypassLapi` SHALL skip LAPI; `bypass` or `bypassAppsec` SHALL skip AppSec; any `captcha` token SHALL set a captcha flag. Skips SHALL add; they MUST NOT cancel each other or a captcha flag. Any `bypassCaptcha` token SHALL set a captcha-bypass flag, and that flag SHALL clear the captcha flag (requirement "bypassCaptcha lets a request through where a captcha would be served"). `bypassCaptcha` skips no leg. Two exceptions drop a skip: a row with a `path` predicate skips nothing on a path with more than one reading (requirement "Action-rule skips need a single-reading path"), and no row skips AppSec under `/crowdsec-internal/challenge/` (`core_plugin_appsec_bot-detection`, "Action rules cannot skip AppSec on the challenge prefix").
- A LAPI skip SHALL skip `LookupRemediation`, `LiveLookup`, missing-subscribed-LAPI failure action, and stream/alone unhealthy failure action.
- An AppSec skip SHALL skip AppSec `Query` and the AppSec body buffer on that path.
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
