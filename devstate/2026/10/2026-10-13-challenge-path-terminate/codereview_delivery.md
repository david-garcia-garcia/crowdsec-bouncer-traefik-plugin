# Delivery

## Motivation
CrowdSec bot-detection challenges call back under `/crowdsec-internal/challenge/`. Those URLs must stay inside the middleware so AppSec can serve them; they must not reach origin.

On this tree, `handleNextServeHTTP` calls `next` whenever AppSec returns nil (HTTP 200, or 500/unreachable with the matching Block flag false). AppSec allows `/crowdsec-internal/challenge/custom.js` when no custom script is configured, so a host-wide middleware still leaks that prefix to the backend.

Leaving it leaks CrowdSec's internal challenge URLs to origin, which the protocol forbids.

Priority: P1 — leaking `/crowdsec-internal/challenge/` to origin is a wrong public contract today

## Implementation
After a nil `appsecQuery` while AppSec is enabled, `handleNextServeHTTP` responds 404 for any `req.URL.Path` with prefix `/crowdsec-internal/challenge/` and does not call `next`. AppSec errors still ban. Paths outside the prefix still call `next` on allow. Trusted IPs still skip in `ServeHTTP` before this function. README documents the 404. Main CI maps GOPATH to the go.mod module path so Yaegi can resolve this fork.

## What this changes
**Operators.** The plugin 404s `/crowdsec-internal/challenge/*` when AppSec is enabled and does not serve the path; covering the host with middleware is not enough without that 404. Clients in `bouncerClientTrustedIps` still skip the plugin.
**Admin users.** None.
**Developers.** `handleNextServeHTTP` 404s `/crowdsec-internal/challenge/` after a nil AppSec query and does not call `next`. This fork's Main workflow maps GOPATH so Yaegi finds `github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin`.
**End users.** Requests under `/crowdsec-internal/challenge/` that AppSec does not serve receive HTTP 404 instead of origin content.
