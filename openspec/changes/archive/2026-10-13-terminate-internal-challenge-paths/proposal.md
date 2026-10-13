## Why

CrowdSec's challenge protocol requires `/crowdsec-internal/challenge/*` never to reach origin. On dest `main`, `handleNextServeHTTP` calls `next` whenever `appsecQuery` returns nil (AppSec HTTP 200, or 500/unreachable with the matching `*Block` flag false). AppSec allows `/crowdsec-internal/challenge/custom.js` when no custom script is configured, so a host-wide middleware leaks that prefix to the backend.

## What Changes

- When AppSec is enabled and `appsecQuery` does not error, a request whose `URL.Path` has prefix `/crowdsec-internal/challenge/` gets HTTP 404 and does not call `next`.
- AppSec errors still ban as today. Paths outside the prefix still call `next` on allow.
- Trusted clients still skip in `ServeHTTP` before this code; no new trusted-IP exception.
- README documents that the plugin 404s the prefix when AppSec does not serve it.
- Dest has no OpenSpec catalog; this change sets `skip_specs: true` and does not add live spec leaves.

## Capabilities

### New Capabilities

None. Dest `main` has no live spec catalog (`skip_specs: true`).

### Modified Capabilities

None.

## Impact

- `bouncer.go` `handleNextServeHTTP` (6 call sites share this body).
- `bouncer_test.go` regression for AppSec 200 on `/crowdsec-internal/challenge/custom.js` vs a normal allow path.
- `README.md` AppSec / bot-detection operator notes.
- Upstream gap vs https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 point 4 (same 404 job on a tree that already relays challenge JSON). This change is not a copy of that patch.
