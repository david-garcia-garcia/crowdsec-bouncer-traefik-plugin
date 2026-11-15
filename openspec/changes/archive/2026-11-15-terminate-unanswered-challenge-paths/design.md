## Context

See proposal.md — Why. Dest is `serveAppSec` in `pkg/bouncer/bouncer.go`. `applyAppsecServeHTTP` already returns false on allow, empty, and unpublished/unreachable passthrough; `ServeHTTP` then calls `next`. Challenge protocol: `knowledge/research/ext_crowdsec_appsec_bot-detection/` (forward `/crowdsec-internal/challenge/*` never to origin). Reproduce: AppSec HTTP 200 `{"action":"allow"}` on `GET /crowdsec-internal/challenge/custom.js` calls `next` (status 200). Upstream report: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 point 4. Do not copy that patch.

## Goals / Non-Goals

**Goals:**
- Terminate unanswered AppSec results on `/crowdsec-internal/challenge/` with 404.
- Keep relay, captcha, and ban envelopes as today.
- Keep allow → `next` for every other path.
- Prove with a unit test next to `TestHandleNextServeHTTPAllowCallsNext`.

**Non-Goals:**
- Copying maxlerebourg PR 403 / root `bouncer.go`.
- Metrics counting, LAPI decision types, `.github/workflows`, closed PR 192.
- A new trusted-IP exception.
- Hardcoding a maxlerebourg checkout path or a vendor GOPATH copy step.

## Decisions

1. **Seam is `serveAppSec`.** After the captcha-rule branch, when AppSec is subscribed, not SkipAppsec, `applyAppsecServeHTTP` returned false, and `req.URL.Path` has prefix `/crowdsec-internal/challenge/`, write 404 and return true. Alternative: 404 inside `applyAppsecServeHTTP` — rejected; that would steal captcha-rule fallthrough to `handleRemediationServeHTTP`. Alternative: 404 in `ServeHTTP` before `next` — rejected; AppSec owns the prefix.

2. **Prefix is `strings.HasPrefix(path, "/crowdsec-internal/challenge/")`.** Ticket Desired names that slash. The regression path is `custom.js` under it. Exact `/crowdsec-internal/challenge` with no trailing slash is out of the named prefix (`explore.md` assumed).

3. **404 is `http.NotFound(rw, req.Request)`.** Stdlib 404 + Not Found body (`explore.md` assumed).

4. **SkipAppsec still calls `next`.** Desired is "when AppSec is in use"; SkipAppsec is not in use (`explore.md` assumed).

5. **Trusted IPs stay the existing `ServeHTTP` skip.** Reuse `trustedClients.Checker`; do not re-derive trust (`explore.md` resolved).

6. **Tests in `pkg/bouncer/zzz_bouncer_test.go`.** Drive `continueAfterLAPIForTest` like `TestHandleNextServeHTTPAllowCallsNext`. Cases: allow on `custom.js` → 404, `next` false; allow on `/protected` → `next` true. Optional: unpublished passthrough on `custom.js` → 404.

## Risks / Trade-offs

- [A captcha action rule on a challenge path after AppSec allow] → 404 is after the captcha-rule branch, so the plugin gate still runs.
- [Failure-action ban on a challenge path] → `applyAppsecServeHTTP` already writes the ban and returns true; no 404.
- [AppSec engine allow for `custom.js` was not re-measured here] → the unit test mocks HTTP 200 allow; protocol still forbids origin for the whole prefix.

## Migration Plan

None. No Traefik config keys. Deploy stops leaking the prefix on the next request.

## Open Questions

None — ticket decisions stand on `explore.md`.
