## REMOVED Requirements

### Requirement: Host+path exclude regexes skip that CrowdSec leg
**Reason**: Replaced by per-leg bypass rule lists that match method, path, host, headers, and cookies on the request. The `host://path` owner is deleted.
**Migration**: Rewrite each exclude string as a `bouncerAppsecBypassRules` / `bouncerLapiBypassRules` entry with `path` on `req.URL.Path`. `health` now matches `/unhealthy`. `example.com://health` will not match path `/health`. No converter. Leftover `bouncerAppsecExcludeRegex` / `bouncerLapiExcludeRegex` YAML is dropped by Traefik unused-key decode.

## ADDED Requirements

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

## MODIFIED Requirements

### Requirement: Bouncer does not own the stream ticker
The per-router bouncer SHALL handle request policy (trusted IPs, ban/captcha pages, whether AppSec runs on pass, request bypass rules, LAPI failure action, Redis fail-closed, and live-cache TTL) and MUST NOT start a process-wide stream ticker. Stream polling remains on the LAPI Client opened by an owner middleware.

#### Scenario: Second subscriber does not start a second ticker
- **WHEN** two bouncing middlewares subscribe to the same published LAPI stream client
- **THEN** only one stream ticker runs for that client incarnation

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
