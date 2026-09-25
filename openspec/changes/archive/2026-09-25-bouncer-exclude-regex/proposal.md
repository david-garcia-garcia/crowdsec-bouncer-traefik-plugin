## Why

Operators cannot skip AppSec or LAPI for one host+path on a bouncing router. Trusted IPs skip both legs; there is no public regex that excludes one CrowdSec leg. Upstream https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/393 is citation only, not a second product ask.

## What Changes

- Public Config strings `bouncerAppsecExcludeRegex` and `bouncerLapiExcludeRegex` (one string each, default empty). Empty after trim: that leg is not excluded.
- `ValidateParams` compiles a non-empty trimmed string as Go RE2 and fails `New` on invalid input. `bouncer.New` compiles once more and stores two `*regexp.Regexp` (nil = no exclude). Do not compile on the request path.
- `ServeHTTP` matches `host://path` with no scheme, no port, no query. Host owner is Traefik/`net/http` `req.Host` (port-stripped with `net.SplitHostPort` when that succeeds). Path owner is `req.URL.Path` (decoded; empty Path treated as `/`). Strip one leading `/` from the path (`example.com` + `/health` → `example.com://health`; empty or `/` → `example.com://`). Do not use AppSec forwarded Host/URI. Do not call `captcha.RequestDomain`.
- A LAPI match skips the whole LAPI remediation path (`LookupRemediation`, `LiveLookup`, missing-subscribed-LAPI failure action, stream/alone unhealthy failure action) and continues at `passOrForcedCaptcha`. An AppSec match in `handleNextServeHTTP` skips `applyAppsecServeHTTP` and calls `next`.
- Order: startup block → GetRemoteIP → trusted-IP skip → forced `b` → LAPI exclude → today's LAPI lookup → pass path AppSec exclude. Do not change trusted-IP skip, forced-decision headers, or failure-action enums.
- Do not hash these strings into LAPI ownership or AppSec identity. Do not adopt a location-list / `EXCLUDE_LOCATION`.
- **Not BREAKING.** Empty default keeps DestBranch behavior.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_bouncer`: request-policy host+path exclude regexes skip that CrowdSec leg independently; match string is port-stripped `req.Host` + `://` + `req.URL.Path` with one leading `/` removed.
- `core_plugin_middleware_config-validation`: non-empty invalid RE2 on either exclude string fails `ValidateParams`.

## Impact

- `pkg/configuration/configuration.go` (public fields alphabetical by json tag; `ValidateParams` compile gate)
- `pkg/bouncer/bouncer.go` (`New` compile; `ServeHTTP` / `handleNextServeHTTP` skip)
- Tests in `pkg/configuration` and `pkg/bouncer`
- README operator knobs
- Usage `knowledge/devdocs/core_plugin_middleware.md` and `knowledge/devdocs/core_plugin_middleware_config-validation.md` (implement / `opd-devdocsimpact`)
- Do not change `pkg/lapi/identity.go` or `pkg/appsec/session.go`
- Do not change `pkg/appsec/query.go` forwarded Host/URI except as needed to build the bouncer match string (not needed: match uses `req.Host` / `req.URL.Path`)
- Neighbors stay as-is: `core_plugin_middleware_forced-decision`, AppSec Query contract, trusted-IP skip
