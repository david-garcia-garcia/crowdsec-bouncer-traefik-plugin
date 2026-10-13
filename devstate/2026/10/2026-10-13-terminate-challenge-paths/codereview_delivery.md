# Delivery

## Motivation
AppSec challenge callbacks live under `/crowdsec-internal/challenge/`. CrowdSec's protocol forwards that prefix to AppSec and never to origin. On this plugin, `applyAppsecServeHTTP` returns false on allow (including `/crowdsec-internal/challenge/custom.js` when AppSec has no custom script) and on failure-action passthrough. `ServeHTTP` then calls `next`, so a host-wide middleware still leaks the prefix to origin.

Leaving it leaks CrowdSec-internal URLs and origin responses for paths that must stay inside AppSec. Reported as point 4 of https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403.

Priority: P1 — challenge callbacks leak to origin today

## Implementation
`serveAppSec` keeps captcha-rule fallthrough and SkipAppsec as they were. After a subscribed AppSec check that did not write, a path under `/crowdsec-internal/challenge/` is `http.NotFound` and true, so `ServeHTTP` does not call `next`. Relay, captcha, and ban still return true from `applyAppsecServeHTTP` first. Paths outside the prefix still call `next` on allow.

## What this changes
**Operators.** Unanswered `/crowdsec-internal/challenge/` is 404 instead of origin when AppSec is enabled. A path-limited middleware still needs a `PathPrefix(/crowdsec-internal/challenge)` router so AppSec sees the callbacks.
**Admin users.** None.
**Developers.** `serveAppSec` 404s unanswered AppSec results on `/crowdsec-internal/challenge/` and does not call `next`.
**End users.** A browser that hits an AppSec-unanswered challenge asset gets 404 instead of the origin page.
