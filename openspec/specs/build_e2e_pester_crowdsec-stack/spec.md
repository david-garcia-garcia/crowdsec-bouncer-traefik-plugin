## Purpose

Defines the Pester real-stack suite that boots Docker Traefik and Crowdsec, loads this plugin as a local Traefik plugin, and asserts remediations against a live LAPI. This is separate from the Traefik-binary + mock-LAPI suite.

## Requirements

### Requirement: Pester suite is separate from mock e2e
The repository SHALL keep `tests/e2e/mock/` and `make e2e_mock` as the mock suite. Real-stack coverage SHALL live entirely under `tests/e2e/real/` (`Test-Integration.ps1`, `docker-compose.test.yml`, `*.Tests.ps1`) and SHALL NOT replace the mock suite or share that folder.

#### Scenario: Mock suite still present
- **WHEN** a reviewer inspects `tests/e2e/mock/` and `.github/workflows/e2e.yml`
- **THEN** `make e2e_mock` still exists and CI still has a job that runs it

#### Scenario: Real suite is its own folder
- **WHEN** a reviewer inspects `tests/e2e/`
- **THEN** Pester cases, the compose file, and `Test-Integration.ps1` are under `tests/e2e/real/` and not at the repository root or mixed into `tests/e2e/mock/`

### Requirement: Real stack boots Traefik and Crowdsec
`tests/e2e/real/config/docker-compose.test.yml` SHALL start Traefik (local plugin bind-mount of the repository root) and Crowdsec. Pester tests SHALL add and delete decisions with `cscli` in the Crowdsec container and send client identity only via `X-Forwarded-For`. Plugin keys in compose labels and file-provider YAML SHALL use the new public names (`lapiEnabled`, `lapiHost`, `lapiMode`, `appsecEnabled`, `bouncerEnabled`, `lapiDefaultDecisionSeconds`, `bouncerClientTrustedIps`, `bouncerBanFilePath`, `captchaEnabled`, `captchaInstanceName`). A captcha-serving route SHALL set `captchaEnabled: true` (empty name fills to the Traefik name). The suite MUST NOT rely on a set `captchaProvider` alone to own captcha.

#### Scenario: Ban then unban on whoami
- **WHEN** the stack is up and a ban decision is added for the test IP
- **THEN** a request to `/whoami` with that `X-Forwarded-For` is forbidden, and after the decision is deleted the same request is allowed

#### Scenario: None mode queries LAPI immediately
- **WHEN** none-mode routes are used and a ban is added
- **THEN** the next request with that `X-Forwarded-For` is forbidden without waiting for a stream interval

#### Scenario: Stream mode uses the stream cache
- **WHEN** stream-mode routes are used and a ban is added
- **THEN** the banned IP is forbidden after the configured stream update interval

#### Scenario: Captcha decision serves the captcha page
- **WHEN** a captcha decision exists for the client
- **AND** the captcha route sets `captchaEnabled: true`
- **THEN** the captcha route returns the captcha HTML rather than a plain allow

#### Scenario: Live mode re-queries after the cached allow expires
- **WHEN** live-mode routes are used, a request is allowed, then a ban is added for that `X-Forwarded-For`
- **THEN** the next request is forbidden only after `lapiDefaultDecisionSeconds`, and a different IP still passes

#### Scenario: Trusted client IP bypasses a ban
- **WHEN** `bouncerClientTrustedIps` includes the test IP and both that IP and an untrusted IP are banned
- **THEN** the trusted `X-Forwarded-For` is allowed and the untrusted one is forbidden

#### Scenario: Custom ban page body and Content-Type
- **WHEN** a ban exists and the route sets `bouncerBanFilePath` to the suite’s custom HTML
- **THEN** the response is forbidden, `Content-Type` is HTML, and the body contains `E2E_CUSTOM_BAN_PAGE_MARKER`

#### Scenario: Real AppSec CRS blocks SQLi
- **WHEN** AppSec is enabled against the Crowdsec CRS inband engine
- **THEN** a benign `/appsec` request is allowed and a SQL-injection query string is forbidden

### Requirement: CI runs Pester and mock as separate jobs
GitHub Actions on pull requests SHALL run `make e2e_mock` in one job and `tests/e2e/real/Test-Integration.ps1` as a matrix of Pester domains `lapi`, `appsec`, `lifecycle`, and `modsec`. Traefik and Crowdsec image tags SHALL match this tree's examples (`traefik:v3.7.11`, `crowdsecurity/crowdsec:v1.8.0`). Each Pester job SHALL boot its own stack. `Assert-PesterDomainPartition` SHALL fail the job when a `*.Tests.ps1` is missing from the partition.

#### Scenario: Pull request runs mock and four Pester domains
- **WHEN** a pull request is opened against this repository
- **THEN** one job runs mock e2e
- **AND** four jobs run the Pester real-stack script (`lapi`, `appsec`, `lifecycle`, `modsec`)

### Requirement: Client address comes from Traefik forwarded headers
Scenario requests SHALL identify the client only via `X-Forwarded-For`. The stack SHALL configure Traefik forwarded headers and the plugin `bouncerForwardedHeadersTrustedIps` so the bouncer uses that header. The harness MUST NOT parse `RemoteAddr` as the bouncer client address.

#### Scenario: Banned spoofed IP is remediating
- **WHEN** a test sends `X-Forwarded-For` for a banned IP
- **THEN** the plugin remediates that request as that IP

### Requirement: Real stack includes a Dragonfly Redis-protocol cache
`tests/e2e/real/config/docker-compose.test.yml` SHALL start Dragonfly (`docker.dragonflydb.io/dragonflydb/dragonfly:v1.40.2`, port 6379, `ulimits.memlock: -1`) in addition to Traefik and Crowdsec. At least one Pester route SHALL set `lapiRedisEnabled` and `lapiRedisHost` to that Dragonfly service. Pester SHALL prove live-mode cache hit/miss against Dragonfly. Client identity SHALL remain only `X-Forwarded-For` (Traefik forwarded headers plus plugin `bouncerForwardedHeadersTrustedIps`).

#### Scenario: Live-mode Redis cache allow then ban after TTL
- **WHEN** the Dragonfly-backed live-mode route is used, a request is allowed, then a ban is added for that `X-Forwarded-For`
- **THEN** the next request is still allowed until `lapiDefaultDecisionSeconds`, after which the same IP is forbidden and a different IP still passes

#### Scenario: Cached ban survives Traefik restart
- **WHEN** a ban is cached in Dragonfly for the test IP and the Traefik container is restarted
- **THEN** a request with that `X-Forwarded-For` is still forbidden without waiting for a new LAPI miss (in-memory-only cache would miss)

### Requirement: Real stack covers Range and header-mapped scopes
The Pester suite SHALL include cases that inject CrowdSec `Range` decisions with `cscli decisions add --range` and at least one header-mapped scope (`--scope` / `--value`) against the live LAPI. A dedicated compose middleware SHALL set `bouncerDecisionScopeHeaders`. Range SHALL be proven in stream mode (cache) and none mode (LAPI `?ip=`). Country matching SHALL use a geoenrich Traefik plugin (traefik-geoblock in enrich mode) that writes the mapped country header from a **public** client IP. The suite MUST NOT inject a client-set country header for that Country case. Client IP identity SHALL remain `X-Forwarded-For`. Nested plugin maps (`bouncerDecisionScopeHeaders`, geoblock `databaseSources`) SHALL be loaded from a file provider.

#### Scenario: Range ban contains the test IP
- **WHEN** a Range ban covers the test client subnet and the request uses that `X-Forwarded-For`
- **THEN** the real-stack route is forbidden, and an IP outside the Range is allowed

#### Scenario: Header-mapped Country ban via geoenrich
- **WHEN** geoblock enrich writes `X-IPCountry` for a public `X-Forwarded-For`, `bouncerDecisionScopeHeaders` maps `Country` to that header, and a Country ban exists for the enriched code
- **THEN** the real-stack route is forbidden for that public IP, and a private IP (country skipped) is allowed

### Requirement: Real stack covers AppSec bot-detection challenge
The Pester suite SHALL boot Crowdsec `v1.8.0` with AppSec bot-detection loaded (`crowdsecurity/appsec-bot-*` or the published 1.8 hub equivalent) in addition to CRS inband. A Traefik route SHALL send `/crowdsec-internal/challenge` through the same AppSec-enabled bouncer middleware, with the service backend on Crowdsec AppSec port 7423 (CRS stays on 7422). Client identity SHALL remain `X-Forwarded-For`. Existing CRS allow/block cases on `/appsec` SHALL remain.

#### Scenario: Challenge is not a silent 403
- **WHEN** bot-detection is loaded and a client without a solved challenge cookie requests the bot-detection route
- **THEN** the response is not a bare operator ban 403 with an empty AppSec body; it carries the AppSec challenge payload (HTML and/or `__crowdsec_challenge` Set-Cookie) or an explicit allow if the engine exempts the client

#### Scenario: CRS inband still blocks SQLi
- **WHEN** AppSec CRS inband is still enabled on `/appsec`
- **THEN** a benign `/appsec` request is allowed and a SQL-injection query string is forbidden

#### Scenario: CRS inband still blocks SQLi in a POST body
- **WHEN** AppSec CRS inband is enabled on `/appsec`
- **AND** the client POSTs a SQL-injection form body
- **THEN** the request is forbidden

#### Scenario: AppSec-only ignores LAPI bans
- **WHEN** `lapiEnabled` is false, `appsecEnabled` is true
- **AND** a LAPI IP ban exists for the client
- **THEN** a benign request is allowed
- **AND** a SQL-injection query string is still forbidden

### Requirement: Real stack covers header-mapped custom scopes
The Pester suite SHALL include a none-mode route whose `bouncerDecisionScopeHeaders` maps `username`, `AS`, and `Country` to request headers (not geoblock enrich). Username and AS SHALL also be proven on the existing stream scope route.

#### Scenario: Username header matches
- **WHEN** a `username` ban `alice` exists and the request sends `X-User: alice`
- **THEN** the route is forbidden, and `X-User: bob` or a missing header is allowed

#### Scenario: Country placeholder does not match
- **WHEN** a Country ban `FR` exists and the request sends `CF-IPCountry: XX`
- **THEN** the route is allowed

### Requirement: Real stack covers LAPI and AppSec failure actions
The Pester suite SHALL include none-mode routes whose LAPI or AppSec host is unreachable, with `bouncerLapiFailureAction` / `bouncerAppsecFailureAction` set to `ban` and `passthrough`. Those routes SHALL set `lapiHttpTimeoutSeconds` and `appsecHttpTimeoutSeconds` to 60 where the suite previously set `httpTimeoutSeconds: 60`, or to 2 on the unreachable-host routes that previously used a short shared timeout. The suite MUST NOT keep `httpTimeoutSeconds`.

#### Scenario: Unreachable LAPI passthrough
- **WHEN** LAPI is unreachable and `bouncerLapiFailureAction` is `passthrough`
- **THEN** the request is allowed

#### Scenario: Unreachable LAPI ban
- **WHEN** LAPI is unreachable and `bouncerLapiFailureAction` is `ban`
- **THEN** the request is forbidden

#### Scenario: Unreachable AppSec passthrough
- **WHEN** AppSec is unreachable and `bouncerAppsecFailureAction` is `passthrough`
- **THEN** the request is allowed

#### Scenario: Unreachable AppSec ban
- **WHEN** AppSec is unreachable and `bouncerAppsecFailureAction` is `ban`
- **THEN** the request is forbidden

### Requirement: Real stack covers captcha POST body, grace, and IPv6 bind
Captcha solve SHALL succeed from the POST body alone (no query-string token). A dedicated short-grace route SHALL challenge again after `captchaGracePeriodSeconds`. Gate bind SHALL accept a different spelling of the same IPv6 address.

#### Scenario: POST-body-only captcha solve
- **WHEN** a captcha decision exists and the client POSTs `dummy-captcha-response` only in the form body
- **THEN** the response is 302 with `crowdsec_captcha_gate` and the next GET reaches the backend

#### Scenario: Captcha grace expires
- **WHEN** the short-grace captcha route is solved
- **THEN** a GET with the gate cookie after `captchaGracePeriodSeconds` serves the challenge again

### Requirement: Instance severance real e2e suite
The repository SHALL provide `tests/e2e/real/instance_severance.Tests.ps1` exercising named LAPI/AppSec slots, late bind, file-provider reload reclaim cases, slot collision, and lifecycle log order from the change requirement matrix (T*, L*, R*, N*, F*, C*, E2/E3). The harness SHALL support rewriting watched dynamic configuration (writable mount or directory) and waiting for Traefik to apply routes without sleep-only synchronization. Lifecycle cases MAY set plugin log level to DEBUG or TRACE and SHALL assert ordered `msg`, `instanceName`, and `incarnation` (and `traefikName` on bouncer lines) in `docker logs traefik-test`. Cases that depend on grace Close SHALL wait at least process reclaim grace plus margin. Dynamic YAML SHALL use `lapiInstanceName`, `appsecInstanceName`, `lapiEnabled`, `appsecEnabled`, and `bouncerEnabled`.

#### Scenario: Named share T2 bans both routes
- **WHEN** an owner publishes `shared` LAPI and AppSec on `/api` and a subscriber bounces `/admin` with the same instance names
- **THEN** a banned test IP receives 403 on both paths with distinct remediation headers per route

#### Scenario: L1 subscriber-only first publish 503 then 403
- **WHEN** the dynamic file first contains only subscribers, then adds the owner in a second publish
- **THEN** requests return 503 before the owner exists and 403 from the decision after the owner publish

#### Scenario: F1 slot collision ERROR
- **WHEN** two middlewares attempt to publish the same LAPI instance name with distinct API keys
- **THEN** the second `New` fails and logs `crowdsec instance name taken` at ERROR without the API key

### Requirement: Real stack covers ModSecurity CRS inspect
The Pester suite SHALL include domain `modsec` with `modsec.Tests.ps1`, `waf_dual.Tests.ps1`, and `waf_backoff.Tests.ps1`. Compose SHALL start an inspect-only Apache CRS sidecar `waf` (OWASP CRS image, drain/inspect-only, not a reverse-proxy to a second origin) and a second one, `waf-flaky`, that only the ModSec backoff route uses. A Traefik route SHALL send traffic through this plugin with `modsecEnabled` / `modsecUrl` (or bounce `modsecInstanceName`). Client identity SHALL remain `X-Forwarded-For`. The partition in `PesterDomains.ps1` SHALL list every `*.Tests.ps1`, including the ModSec files. Nginx-drain MAY be added when the same whoami/Traefik harness can switch. Bombardier benches MUST NOT be product tests.

#### Scenario: Clean GET is allowed
- **WHEN** the ModSec route receives a benign GET
- **THEN** the backend whoami response is allowed
- **AND** the response has no remediation header

#### Scenario: CRS traversal is blocked
- **WHEN** the ModSec route receives `?test=../etc`
- **THEN** the response is the sidecar 403 with `ban:modsec`
- **AND** whoami is not called
- **AND** the sidecar log names CRS rule 930110 for that URI

#### Scenario: CRS judges a body on GET
- **WHEN** a GET to the ModSec route carries a body
- **THEN** the plugin forwards that body to the sidecar
- **AND** the response is HTTP 403 with `ban:modsec`
- **AND** the sidecar log names CRS rule 920170 for that URI

#### Scenario: A clean OPTIONS body passes
- **WHEN** an OPTIONS request carries a clean JSON body
- **THEN** the request is allowed

#### Scenario: A body payload reaches CRS and the body reaches origin
- **WHEN** a POST body carries an XSS payload
- **THEN** the response is HTTP 403 with `ban:modsec` and the sidecar logs a 941xxx rule
- **AND** a clean POST body is echoed by the origin unchanged

#### Scenario: Body over limit is 413
- **WHEN** the ModSec route sets a small `modsecBodyLimit`
- **AND** the client POST exceeds that limit
- **THEN** the response is HTTP 413
- **AND** the sidecar logs no rule for that URI

#### Scenario: Failure actions on a down sidecar
- **WHEN** the sidecar URL is unreachable
- **THEN** `bouncerModsecFailureAction` `passthrough` lets the request reach whoami with no remediation header
- **AND** `ban` serves the custom ban page with HTTP 403, reason `MODSEC`, and `ban:modsec-failure`
- **AND** `captcha` serves the captcha page with `captcha:modsec-failure`

#### Scenario: WebSocket through the ModSec leg
- **WHEN** a client opens a WebSocket on a ModSec route backed by an echo server
- **THEN** the handshake is inspected and two text frames are echoed on one connection
- **AND** a handshake carrying a CRS payload is blocked with HTTP 403
- **AND** a lone `Upgrade: websocket` header without a Connection upgrade token is still inspected

#### Scenario: Action-rule skip bypasses CRS
- **WHEN** a matching `bypassModsec` (or `bypass`) rule matches
- **AND** the query string would otherwise trip CRS
- **THEN** the request is allowed
- **AND** the same payload on a path the rule does not match is blocked with `ban:modsec`

### Requirement: Real stack covers AppSec and ModSec on one router
Compose SHALL run an AppSec listener on 7424 (`acquis.d/appsec-dual.yaml`) with appsec config `e2e/dual-vpatch`: no CRS, and `DropRequest` when the path contains `appsec-drop`. A file-provider router SHALL use that listener and the CRS sidecar `waf` on one middleware, with an echo origin. The cases SHALL tell the legs apart by `ban:appsec` and `ban:modsec`, and SHALL prove that the sidecar was not called by a unique marker missing from the sidecar log, after a positive control.

#### Scenario: Both legs run in order
- **WHEN** a clean request hits the dual router
- **THEN** the origin answers
- **AND** a CRS payload on a path AppSec allows is blocked with `ban:modsec`

#### Scenario: An AppSec block never reaches the sidecar
- **WHEN** a path contains `appsec-drop` and a CRS payload
- **THEN** the response is HTTP 403 with `ban:appsec`
- **AND** the sidecar log has no line for that request

#### Scenario: Bypass is per leg
- **WHEN** `bypassAppsec` matches
- **THEN** the AppSec drop path is allowed and a CRS payload is still blocked with `ban:modsec`
- **AND** when `bypassModsec` matches, a CRS payload is allowed and the AppSec drop path is still blocked with `ban:appsec`

#### Scenario: Both legs share one body
- **WHEN** a POST body carries an XSS payload that only CRS detects
- **THEN** the response is `ban:modsec` and the sidecar logs an XSS rule for that request
- **AND** a clean POST body is echoed by the origin after both legs read it

### Requirement: Real stack covers the admission gate of both WAF legs
`waf_backoff.Tests.ps1` SHALL cover the AppSec gate with its shipped defaults against `waf-5xx`, and one real outage and recovery per leg. Each outage SHALL stop and start a container only its own route uses: `appsec-flaky-test` (nginx proxy to `crowdsec:7422`) for AppSec, `waf-flaky-test` for ModSec. `AfterAll` SHALL start that container again. Cycle routes SHALL use a 10 s cooldown and the `ban` failure action, and SHALL run the other WAF leg on the same router.

#### Scenario: Default AppSec gate
- **WHEN** a route sets no `appsecUnhealthyBackOffPeriodSecs` and no `bouncerAppsecFailureAction`, and AppSec answers 503
- **THEN** at most 5 requests reach the listener, each banned
- **AND** later requests reach the origin without a ban
- **AND** a fresh stack logs exactly one `crowdsec appsec backoff started` line for that middleware

#### Scenario: AppSec outage and recovery
- **WHEN** `appsec-flaky-test` is stopped
- **THEN** 5 requests answer HTTP 403 with `ban:appsec-failure`
- **AND** the next clean request reaches the origin with no remediation header, while a CRS payload is still blocked with `ban:modsec`
- **AND** after the container starts and the cooldown ends, AppSec answers `ban:appsec` again
- **AND** Traefik logs exactly one `crowdsec appsec backoff started` and one `crowdsec appsec backoff ended` line for that outage

#### Scenario: ModSec outage and recovery
- **WHEN** `waf-flaky-test` is stopped
- **THEN** 5 requests answer HTTP 403 with `ban:modsec-failure`
- **AND** the next clean request and a CRS payload both reach the origin, while the AppSec drop path is still blocked with `ban:appsec`
- **AND** after the container starts and the cooldown ends, the sidecar answers `ban:modsec` again
- **AND** Traefik logs exactly one `crowdsec modsec backoff started` and one `crowdsec modsec backoff ended` line for that outage

### Requirement: Real stack covers the Redis rate limit
The real-stack Pester suite SHALL run the rate-limit leg inside Traefik's plugin loader against the stack's Dragonfly service, configured through the file provider (the bucket list is a list of objects with nested lists, which Docker labels do not decode). It SHALL prove: a `deny` bucket answers `rateLimitStatusCode` with `Retry-After` and remediation header `ban:ratelimit:<bucket>` after `requests` hits; a different client address is not limited by that counter; a `bypassRateLimit` action rule lets the over-limit client through; a `log` bucket never denies; an unreachable Redis with `rateLimitFailureAction: passthrough` lets the request through and with `ban` answers `ban:ratelimit-failure`; and a rate-limit deny reaches `cscli metrics` as a drop with origin `plugin:ratelimit:<bucket>`. Each case SHALL use a client address no other case uses, so counters left in Dragonfly by an earlier run or case cannot change the result. The file SHALL be listed in one CI Pester domain.

#### Scenario: Deny after the limit on real Traefik
- **WHEN** a client sends `requests + 1` requests to a route whose `deny` bucket allows `requests` per window
- **THEN** the last response is 429 with `Retry-After` equal to the counter's next admit (for 4 hits on a limit of 3 per minute: the time to the window end plus 30s, within 1s)
- **AND** the remediation header is `ban:ratelimit:<bucket>`

#### Scenario: Redis down with passthrough
- **WHEN** the middleware points `rateLimitRedisHost` at a port where nothing listens and `rateLimitFailureAction` is `passthrough`
- **THEN** requests reach the backend

#### Scenario: Deny is a drop in cscli
- **WHEN** a rate-limit deny happens on a router with a LAPI client and a short metrics interval
- **THEN** `cscli metrics` for that bouncer shows a dropped count under origin `plugin:ratelimit:<bucket>`
