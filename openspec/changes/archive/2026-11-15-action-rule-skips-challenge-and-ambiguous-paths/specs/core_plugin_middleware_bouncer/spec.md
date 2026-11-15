## ADDED Requirements

### Requirement: Action-rule skips need a single-reading path
A matching action row that has a `path` predicate SHALL contribute its `bypass`, `bypassLapi`, and `bypassAppsec` skips only when the request path has a single reading. The path has a single reading when `req.URL.EscapedPath()` equals `req.URL.Path` (the client percent-encoded nothing), every byte is one of `A-Z a-z 0-9 - . _ ~ ! $ & ' ( ) + , = : @ /`, `path.Clean` (keeping a trailing slash) leaves it unchanged, and no segment is only dots. Otherwise that row's skips SHALL be ignored for the request, because its regex read one path and the backend may serve another (a Java servlet backend reads `/healthz/..;/admin` as `/admin`; an IIS backend reads `\` as `/`). That row's `captcha` token SHALL still apply. A row without a `path` predicate SHALL keep its skips. `ban` rows SHALL be unchanged. `ActionMatch.AmbiguousPathName` SHALL name the first row whose skips were ignored, and ServeHTTP SHALL log TRACE `foldActionRules` with attr `ambiguousPathRule`. Anchoring the regex does not prevent this; the check is on the request path, not on the pattern. Upstream: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/413 (single-reading rule of `crowdsecAppsecExcludedLocations`).

#### Scenario: Java path-parameter traversal does not skip AppSec
- **WHEN** `bouncerActionRules` contains `{name: healthz, path: "^/healthz(/|$)", action: [bypassAppsec]}`
- **AND** the request path is `/healthz/..;/admin` (or `/healthz/%2E%2E;/admin`, `/healthz/..%5Cadmin`, `/healthz%2Fadmin`, `/healthz/%252e%252e/admin`)
- **THEN** AppSec `Query` runs for that request

#### Scenario: Plain subpath still skips
- **WHEN** `bouncerActionRules` contains `{name: healthz, path: "^/healthz(/|$)", action: [bypassAppsec]}`
- **AND** the request path is `/healthz/live`
- **THEN** the AppSec leg is skipped

#### Scenario: Captcha token survives an ambiguous path
- **WHEN** a matching row is `{path: "^/healthz/", action: [captcha, bypassLapi]}`
- **AND** the request path is `/healthz/..;/admin`
- **THEN** the captcha rule applies
- **AND** the LAPI leg is not skipped

#### Scenario: Rule without a path predicate keeps its skip
- **WHEN** a matching row is `{host: "^internal\.example$", action: [bypassLapi]}`
- **AND** the request path is `/healthz/..;/admin`
- **THEN** the LAPI leg is skipped
