## Why

CrowdSec's challenge protocol forwards `/crowdsec-internal/challenge/*` to AppSec and never to origin. On master, AppSec allow (including `/crowdsec-internal/challenge/custom.js` when no custom script is configured) and AppSec failure-action passthrough both return from `applyAppsecServeHTTP` without writing, and `ServeHTTP` then calls `next`. Host-wide middleware is therefore not enough to keep that prefix off origin.

## What Changes

- When AppSec is in use for the request and the URL path is under `/crowdsec-internal/challenge/`, and AppSec did not write a relayed envelope or a ban, respond 404 and do not call `next`.
- A real challenge, captcha, or ban envelope for that path is still written as today.
- Paths outside the prefix are unchanged. Trusted IPs that already skip the bouncer before this code stay as they are. No new trusted-IP exception.
- Update the live specs and the README sentence that says the prefix is safe whenever the middleware covers the host.
- Regression test: AppSec HTTP 200 on `/crowdsec-internal/challenge/custom.js` is 404 and `next` is not called; a normal allowed path still calls `next`.
- **Not BREAKING.** No new Traefik config keys.
- Do not copy maxlerebourg PR 403's patch. Do not edit `.github/workflows`. Out of scope: metrics counting, LAPI decision types, closed PR 192.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_appsec_bot-detection`: unanswered AppSec results on `/crowdsec-internal/challenge/` SHALL be 404 and MUST NOT call `next`; allow/empty 200 on other paths still call `next`.
- `core_plugin_appsec_failure-action`: passthrough SHALL NOT call `next` when AppSec was in use and the path is under `/crowdsec-internal/challenge/` (404 instead).

## Impact

- `pkg/bouncer/bouncer.go` (`serveAppSec`)
- `pkg/bouncer` tests next to `TestHandleNextServeHTTPAllowCallsNext`
- Live specs `openspec/specs/core_plugin_appsec_bot-detection/` and `openspec/specs/core_plugin_appsec_failure-action/`
- `README.md` bot-detection sentence
- Usage packet `knowledge/devdocs/core_plugin_appsec.md` (already says never send the prefix to origin; How-to-use allow bullet needs the carve-out)
- Upstream report: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 point 4
