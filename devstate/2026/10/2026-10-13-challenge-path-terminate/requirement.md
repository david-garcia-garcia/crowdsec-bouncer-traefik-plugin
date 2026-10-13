# Requirement
IssueKey: 2026-10-13-challenge-path-terminate

## Problem
CrowdSec's bot-detection challenge protocol requires `/crowdsec-internal/challenge/*` to be forwarded to AppSec and never to origin. When AppSec does not itself answer that path, the bouncer must terminate it. This fork, after an AppSec allow (or a nil decision), calls `next`, so a host-wide middleware still leaks those URLs to origin. AppSec HTTP 200 on `/crowdsec-internal/challenge/custom.js` (the custom-script path AppSec allows when no custom script is configured) returned 200 and ran the next handler. The same leak happens when `bouncerAppsecFailureAction` is `passthrough` and AppSec is unreachable or returns a status treated as allow.

## Current (code)
- `pkg/bouncer/bouncer.go` `applyAppsecServeHTTP`: `decision == nil || decision.Action == "" || decision.Action == appsec.ActionAllow` returns false; `ServeHTTP` then calls `b.next.ServeHTTP` with no path check.
- `pkg/bouncer/zzz_bouncer_test.go` `TestHandleNextServeHTTPAllowCallsNext`: AppSec HTTP 200 `{"action":"allow"}` on a normal path calls next (no `/crowdsec-internal/challenge/` case).
- `pkg/appsec/query.go` `resultForFailureAction` / `appsecAllow`: `passthrough` on unreachable or unexpected AppSec failure returns an allow decision, which takes the same next path.
- `README.md` (Bot detection paragraph): "If the middleware already covers every path of the host, you are done."
- `tests/e2e/real/appsec.Tests.ps1` `Should keep challenge assets off the origin whoami`: GET `/crowdsec-internal/challenge/fpscanner.js` must not match `Hostname:` (whoami). Traefik routes that prefix to the AppSec listener (`tests/e2e/real/config/docker-compose.test.yml` `PathPrefix(\`/crowdsec-internal/challenge\`)`), so the test does not prove the plugin itself returns 404.
- `openspec/specs/core_plugin_appsec_bot-detection/spec.md`: relays challenge/captcha/ban envelopes; does not require 404 when AppSec allows a challenge-prefix path.
- `pkg/bouncer/bouncer.go` `ServeHTTP`: trusted IPs call `next` before LAPI/AppSec; no extra trusted-IP exception on the challenge prefix.

## Desired
- When AppSec is in use for this request and the URL path is under `/crowdsec-internal/challenge/`, and AppSec did not produce a relayed envelope or a ban the bouncer writes, the bouncer responds 404 and does not call next.
- A real challenge, captcha, or ban envelope for that path is still written as today.
- Paths outside the prefix are unchanged (AppSec allow still calls next).
- Do not add a new trusted-IP exception; the existing trusted-client skip stays as it is.
- Update the live spec and the README sentence that tells operators the prefix is safe whenever the middleware covers the host.
- Regression: AppSec allow (HTTP 200) on `/crowdsec-internal/challenge/custom.js` is 404 and next is not called; a normal path that AppSec allows still calls next.

## Affected
- `pkg/bouncer/bouncer.go` (`applyAppsecServeHTTP` / `serveAppSec` / `ServeHTTP` tail)
- `pkg/bouncer/zzz_bouncer_test.go` (allow-calls-next coverage)
- `openspec/specs/core_plugin_appsec_bot-detection/spec.md`
- `README.md` bot-detection paragraph
- `knowledge/devdocs/core_plugin_appsec.md` (usage: "Do not send `/crowdsec-internal/challenge/*` to origin")

## Out of scope
- New trusted-IP exception or changing when trusted clients skip the bouncer.
- Changing how challenge/captcha/ban envelopes are written.
- Changing Traefik routing in e2e (`PathPrefix` to the AppSec listener).
- Copying upstream `maxlerebourg/crowdsec-bouncer-traefik-plugin#403` as a patch.

## Unknowns
- Exact path match: trailing slash, `/crowdsec-internal/challenge` with no extra segment, query string, case.
- Whether `match.SkipAppsec` or an unpublished AppSec client still 404s (ticket says "when AppSec is in use for this request").
- Whether passthrough-as-allow on the prefix is 404 in the same branch as explicit `action: allow`.
- 404 body and headers (plain `http.NotFound` vs empty body).
- Fork gap versus upstream PR 403 (how they terminate; we must not claim we copied their patch).

## Tensions
- README tells operators a host-wide middleware is enough; that layout is the leak.
- Spec/devdocs already say do not send the prefix to origin, but allow still calls next.
- E2e `Should keep challenge assets off the origin whoami` is cited as coverage; it only proves Traefik routing, not plugin 404.
- Upstream PR 403 / issue 402 point 4 is the same job on the parent repo; this fork must close the same gap on its own `applyAppsecServeHTTP` allow path, not by importing their diff.
