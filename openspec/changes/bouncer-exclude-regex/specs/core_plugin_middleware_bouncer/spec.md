## ADDED Requirements

### Requirement: Host+path exclude regexes skip that CrowdSec leg
The bouncer SHALL expose public Config strings `bouncerAppsecExcludeRegex` and `bouncerLapiExcludeRegex` (one string each, default empty). Empty after trim SHALL exclude nothing for that leg. `bouncer.New` SHALL compile each non-empty trimmed string once with Go `regexp.Compile` and store the compiled value; empty SHALL stay unset (no exclude). ServeHTTP SHALL treat a stored regex as a match when unanchored `MatchString` is true against host + `://` + path with no scheme, no port, and no query. `host` SHALL be `req.Host` after `net.SplitHostPort` when that call succeeds, otherwise `req.Host` as Traefik/`net/http` already set it. `path` SHALL be `req.URL.Path` (decoded); empty Path SHALL be `/`. The plugin MUST NOT strip the path's leading slash. Concatenate host, then the literal `://`, then path (`example.com` + `/health` → `example.com:///health`). The plugin MUST NOT rebuild Host from `X-Forwarded-Host`, AppSec `X-Crowdsec-Appsec-Host` / `X-Crowdsec-Appsec-Uri`, `URL.Host`, or `captcha.RequestDomain`. The plugin MUST NOT use `URL.String()`, `RequestURI`, or `EscapedPath` as the path. A LAPI match SHALL skip `LookupRemediation`, `LiveLookup`, missing-subscribed-LAPI failure action, and stream/alone unhealthy failure action, and SHALL continue at `passOrForcedCaptcha`. An AppSec match SHALL skip AppSec `Query` and call `next`. Exclude SHALL run after startup block, GetRemoteIP, trusted-IP skip, and forced `b`. Forced `c` SHALL still apply on the pass path after a LAPI exclude. The two regexes SHALL be independent. These strings MUST NOT enter LAPI ownership or AppSec identity keys. The plugin MUST NOT compile on the request path.

#### Scenario: Empty LAPI exclude still looks up
- **WHEN** `bouncerLapiExcludeRegex` is empty or whitespace-only
- **AND** the bouncer subscribed to LAPI
- **AND** `bouncerDecisionHeader` is empty or the named header is not exact trimmed `b`
- **THEN** ServeHTTP still consults `LookupRemediation` or `LiveLookup` as today

#### Scenario: LAPI exclude skips stream store and unhealthy failure
- **WHEN** `bouncerLapiExcludeRegex` is `example\.com:///health`
- **AND** `req.Host` is `example.com` and `req.URL.Path` is `/health`
- **AND** `lapiMode` is stream or alone
- **THEN** ServeHTTP does not call `LookupRemediation`
- **AND** it does not apply a store hit
- **AND** it does not take stream-unhealthy failure action
- **AND** it continues at `passOrForcedCaptcha`

#### Scenario: LAPI exclude skips live and none lookup
- **WHEN** `bouncerLapiExcludeRegex` is `example\.com:///health`
- **AND** `req.Host` is `example.com` and `req.URL.Path` is `/health`
- **AND** `lapiMode` is live or none
- **THEN** ServeHTTP does not call `LiveLookup`
- **AND** it continues at `passOrForcedCaptcha`

#### Scenario: AppSec exclude skips Query on the pass path
- **WHEN** `bouncerAppsecExcludeRegex` is `example\.com:///health`
- **AND** `req.Host` is `example.com` and `req.URL.Path` is `/health`
- **AND** the bouncer subscribed to AppSec
- **AND** the request reaches `handleNextServeHTTP`
- **THEN** ServeHTTP does not call AppSec `Query`
- **AND** it calls `next`

#### Scenario: LAPI exclude does not skip AppSec
- **WHEN** `bouncerLapiExcludeRegex` matches and `bouncerAppsecExcludeRegex` does not
- **AND** the bouncer subscribed to AppSec
- **AND** the request reaches the pass path
- **THEN** AppSec `Query` still runs

#### Scenario: Forced b still bans before LAPI exclude
- **WHEN** `bouncerDecisionHeader` forces `b`
- **AND** `bouncerLapiExcludeRegex` would match this request
- **THEN** the response is the ban page
- **AND** ServeHTTP does not apply the LAPI exclude skip

#### Scenario: Forced c still captchas after LAPI exclude
- **WHEN** `bouncerLapiExcludeRegex` matches
- **AND** `bouncerDecisionHeader` forces `c`
- **AND** lookup is skipped
- **THEN** the pass path still applies forced captcha

#### Scenario: Port is stripped from Host
- **WHEN** `req.Host` is `example.com:443` and `req.URL.Path` is `/health`
- **AND** `bouncerLapiExcludeRegex` is `^example\.com:///health$`
- **THEN** the match string is `example.com:///health`
- **AND** the LAPI leg is skipped

#### Scenario: Query string is not in the match string
- **WHEN** `req.Host` is `example.com`, `req.URL.Path` is `/health`, and the request has query `a=1`
- **AND** `bouncerAppsecExcludeRegex` is `^example\.com:///health$`
- **THEN** the match string is `example.com:///health`
- **AND** AppSec `Query` is skipped

## MODIFIED Requirements

### Requirement: Bouncer does not own the stream ticker
The per-router bouncer SHALL handle request policy (trusted IPs, ban/captcha pages, whether AppSec runs on pass, host+path exclude regexes, LAPI failure action, Redis fail-closed, and live-cache TTL) and MUST NOT start a process-wide stream ticker. Stream polling remains on the LAPI Client opened by an owner middleware.

#### Scenario: Second subscriber does not start a second ticker
- **WHEN** two bouncing middlewares subscribe to the same published LAPI stream client
- **THEN** only one stream ticker runs for that client incarnation

### Requirement: Live stream and alone lookup uses one Store entry
When `lapiMode` is live, stream, or alone, and a configured `bouncerDecisionHeader` does not force `b` on this request, and the LAPI exclude regex does not match, the bouncer SHALL resolve memoized remediation through one `lapi.Client.LookupRemediation` that delegates to `Store.LookupRemediation`. It MUST NOT call `UsesLiveSnapshot`, MUST NOT branch between a live snapshot and a cache Client, and MUST NOT duplicate merge semantics in the bouncer. Stream and alone miss SHALL fall through to stream-healthy / failure-action. Live miss SHALL call `LiveLookup`, which returns `(kind, origin, error)` fields. None mode SHALL call `LiveLookup` every request (no memo read) unless that same header forced `b` or the LAPI exclude regex matches. Forced `b` or `c` is owned by `core_plugin_middleware_forced-decision`; this leaf MUST NOT restate that owner SHALL. `bouncer.New` SHALL copy `LapiDefaultDecisionSeconds` onto `Bouncer.defaultDecisionSeconds` and pass that into `LiveLookup`; the parameter name SHALL stay `defaultDecisionSeconds`.

#### Scenario: Stream mode uses Store lookup
- **WHEN** a stream bouncer handles a request and the DecisionStore is memory-backed
- **AND** `bouncerDecisionHeader` is empty or the named header is not exact trimmed `b`
- **AND** `bouncerLapiExcludeRegex` is empty or does not match
- **THEN** remediation is resolved through `LookupRemediation` only

#### Scenario: Stream mode Redis uses the same entry
- **WHEN** a stream bouncer handles a request and the DecisionStore is Redis-backed
- **AND** `bouncerDecisionHeader` is empty or the named header is not exact trimmed `b`
- **AND** `bouncerLapiExcludeRegex` is empty or does not match
- **THEN** remediation is resolved through the same `LookupRemediation`

#### Scenario: Live memo then LiveLookup
- **WHEN** `lapiMode` is live and the Store misses
- **AND** `bouncerDecisionHeader` is empty or the named header is not exact trimmed `b`
- **AND** `bouncerLapiExcludeRegex` is empty or does not match
- **THEN** the bouncer calls `LiveLookup` and remediates from kind and origin fields

#### Scenario: None mode skips Store memo
- **WHEN** `lapiMode` is none
- **AND** `bouncerDecisionHeader` is empty or the named header is not exact trimmed `b`
- **AND** `bouncerLapiExcludeRegex` is empty or does not match
- **THEN** the bouncer does not use a Store hit as the primary remediation check
- **AND** it calls `LiveLookup` for kind and origin
