# Requirement
IssueKey: 2026-10-13-terminate-challenge-paths

## Problem
AppSec challenge callback URLs under `/crowdsec-internal/challenge/` must never reach origin. On master, `applyAppsecServeHTTP` returns false on allow / nil decision, and `ServeHTTP` then calls `next`. AppSec HTTP 200 (including `/crowdsec-internal/challenge/custom.js` when no custom script is configured) therefore leaks that prefix to origin. The same leak happens when `bouncerAppsecFailureAction` is passthrough and AppSec is unpublished, unreachable, or otherwise continues as allow.

## Current (code)
- `pkg/bouncer/bouncer.go` `ServeHTTP`: trusted IPs skip LAPI and AppSec and always call `next` (lines 199–206). After LAPI and AppSec, any remaining request calls `next` (line 227).
- `pkg/bouncer/bouncer.go` `serveAppSec`: when AppSec is subscribed and not skipped, returns `applyAppsecServeHTTP`. False means `ServeHTTP` calls `next` (lines 295–304, 221–227).
- `pkg/bouncer/bouncer.go` `applyAppsecServeHTTP`: nil client + `FailureActionPassthrough` returns false (lines 443–446). After Query, `decision == nil || Action == "" || Action == allow` returns false (lines 472–473). Ban, empty-challenge ban, and relay of challenge/captcha return true and write the response (lines 475–491).
- `pkg/appsec/query.go` `appsecAllow` / empty HTTP 200: Query turns empty or allow JSON into `ActionAllow` so the bouncer continues (lines 84–87; spec `openspec/specs/core_plugin_appsec_bot-detection/spec.md` "Empty 200 still passes").
- `pkg/bouncer/zzz_bouncer_test.go` `TestHandleNextServeHTTPAllowCallsNext`: AppSec `{"action":"allow"}` on a normal path calls `next`.
- `pkg/bouncer/zzz_servehttp_gaps_test.go` `TestHandleNextServeHTTP_UnpublishedAppSecUsesFailureAction` passthrough: unpublished AppSec calls `next`.
- `README.md` line 155: "If the middleware already covers every path of the host, you are done."
- `openspec/specs/core_plugin_appsec_bot-detection/spec.md`: allow / empty 200 "the request proceeds to `next`" with no challenge-prefix exception.
- `openspec/specs/core_plugin_appsec_failure-action/spec.md`: passthrough "the request proceeds to `next`".
- `knowledge/devdocs/core_plugin_appsec.md` gotcha: "Do not send `/crowdsec-internal/challenge/*` to origin" — the code does not enforce that on allow/passthrough.

## Desired
When AppSec is in use for this request and the URL path is under `/crowdsec-internal/challenge/`, and AppSec did not itself produce a response the bouncer is relaying or a ban the bouncer is writing, respond 404 and do not call `next`. A real challenge, captcha, or ban envelope for that path is still written as today. Paths outside the prefix are unchanged. Do not add a new trusted-IP exception; trusted IPs that already skip the bouncer before this code stay as they are.

Update the live spec and the README sentence that says the prefix is safe whenever the middleware covers the host.

Regression test: AppSec HTTP 200 on `/crowdsec-internal/challenge/custom.js` is 404 and `next` is not called. A normal path that AppSec allows still calls `next`. Run the tests on this machine.

## Affected
- `pkg/bouncer/bouncer.go` `applyAppsecServeHTTP` (and/or its caller `serveAppSec`)
- `pkg/bouncer` tests next to `TestHandleNextServeHTTPAllowCallsNext`
- `openspec/specs/core_plugin_appsec_bot-detection/spec.md` (and possibly `core_plugin_appsec_failure-action`)
- `README.md` bot-detection sentence
- `knowledge/devdocs/core_plugin_appsec.md` (usage already claims no origin leak)

## Out of scope
- Metrics counting
- LAPI decision types
- `.github/workflows`
- Closed GitHub PR 192 (targeted `main`, patched root `bouncer.go`)
- Copying upstream maxlerebourg PR 403's patch
- A new trusted-IP exception
- Hardcoding a maxlerebourg checkout path or a vendor GOPATH copy step

## Unknowns
- Exact prefix match: ticket says `/crowdsec-internal/challenge/` (trailing slash). Whether `/crowdsec-internal/challenge` with no slash is in scope.
- Whether `match.CaptchaName != ""` returning false so the plugin captcha gate runs counts as "a real captcha envelope" (ticket: captcha is still written as today).
- Whether SkipAppsec on a challenge path still leaks to origin (ticket: "when AppSec is in use for this request").
- Whether AppSec actually returns allow for `/crowdsec-internal/challenge/custom.js` on this engine version (ticket claim; research `knowledge/research/ext_crowdsec_appsec_bot-detection/` exists; not re-measured this prepare).
- README wording after the host-wide-cover sentence is no longer true.

## Tensions
- README and bot-detection spec treat host-wide middleware as sufficient; the ticket says host-wide coverage still leaks `custom.js` to origin.
- Failure-action spec says passthrough continues to `next` for every path; the ticket carves challenge-prefix paths out of that continue.
- Devdocs already say never send the prefix to origin; the live spec and code do not.
- Upstream https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 point 4 is the source of the ask; do not copy that patch. Closed fork PR 192 targeted `main` and the old root `bouncer.go`; this change is on `master` / `pkg/bouncer/bouncer.go`.
