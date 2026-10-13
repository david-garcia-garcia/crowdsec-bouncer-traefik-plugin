# Explore

## Concepts

Dest `main` still has the root `bouncer.go` layout (module `github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin`). There is no `pkg/bouncer`, no `openspec/`, and no `knowledge/devdocs/` on this branch. Prepare's `requirement.md` current-behavior paths (`pkg/bouncer/bouncer.go`, `openspec/specs/core_plugin_appsec_bot-detection`) name the caller checkout's refactor branch, not dest.

Units this change touches:

- `Bouncer.handleNextServeHTTP` — `bouncer.go`. After a successful AppSec query (`appsecQuery` nil error), calls `next`. AppSec 403/500-with-block already ban.
- `appsecQuery` — `bouncer.go`. HTTP 200 (and 500/unreachable when the matching `*Block` flag is false) return nil; no structured JSON envelope is parsed on dest.
- Trusted-client skip — `Bouncer.ServeHTTP` (`bouncer.go` ~357): `clientPoolStrategy.Checker.Contains` then `next`, before `handleNextServeHTTP`. Owner of that skip. Do not add a second exception.
- Client address — `ip.GetRemoteIP` then the `remoteIP` argument. This change does not re-derive it.
- Request path — `req.URL.Path` on the inbound `*http.Request`. Query string is not in Path.

Seam:

```
ServeHTTP
  trusted? → next
  LAPI ban/captcha? → write
  handleNextServeHTTP
    appsecEnabled? appsecQuery
      err → handleBanServeHTTP (APPSEC)
      nil → next          ← leak for /crowdsec-internal/challenge/*
```

Call sites of `handleNextServeHTTP`: 6 in `bouncer.go` (lines 363, 375, 386, 397, 408, 480). One function body; changing it covers all. Roots searched: dest `bouncer.go`.

Reproduce: `go test -mod=vendor -run TestThrowawayChallengePathAllowLeaksToNext .` on dest (throwaway, deleted). AppSec HTTP 200 on `GET /crowdsec-internal/challenge/custom.js` called `next` (status 200). Reproduced.

Outside facts: CrowdSec challenge protocol (bouncer must forward `/crowdsec-internal/challenge/*` and never send it to origin; AppSec 200 is allow). Upstream https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 point 4 404s that prefix after AppSec did not answer, via `strings.HasPrefix(path, "/crowdsec-internal/challenge/")` and `http.NotFound`. Dest has no JSON challenge relay (unlike that PR's base); this run takes only the 404-on-allow/passthrough behavior, not their captcha/metrics/unknown-type commits and not their patch.

## Decisions

- Place the 404 in `handleNextServeHTTP` after `appsecQuery` returns nil and only when `appsecEnabled`: if `req.URL.Path` has prefix `/crowdsec-internal/challenge/`, `http.NotFound` and do not call `next`.
- Keep today's ban on AppSec error (403, 500-with-block, unreachable-with-block). Dest does not relay a challenge/captcha JSON envelope; there is nothing extra to preserve on those paths.
- Prefix includes the trailing slash (ticket + upstream + official `/*`). Exact `/crowdsec-internal/challenge` without a further segment is not this prefix. Query is ignored because it is not in `URL.Path`.
- Do not 404 when AppSec is off (`appsecEnabled` false): AppSec is not in use.
- Do not add a trusted-IP exception; `ServeHTTP` already skips before this code.
- Operator docs: dest README has no “middleware covers the host, you are done” sentence. Add bot-detection guidance that the plugin 404s the prefix when AppSec does not serve it. Do not bootstrap `openspec/` on dest (no live catalog).
- Regression tests in `bouncer_test.go`: AppSec 200 on `/crowdsec-internal/challenge/custom.js` is 404 and `next` is not called; a normal path that AppSec allows still calls `next`.
- Rejected: copying upstream PR 403 as a patch (ticket forbids; dest also lacks their challenge-JSON / captcha-action / metrics scaffolding).
- Rejected: 404 in `appsecQuery` (that function's job is the AppSec round-trip, not client responses).
- Live contract: no live contract on dest (`openspec/` absent).

## Open questions

- Q: Who already owns the client address this handler uses?
  Rank: bounded asked — existing GetRemoteIP output, 6 handleNextServeHTTP callers in bouncer.go; Desired says AppSec-in-use request
  Decision: resolved — reuse `ip.GetRemoteIP` / the `remoteIP` argument; do not parse `RemoteAddr` or forwarded headers again.
  By: explore

- Q: Which path string is the prefix check's input?
  Rank: additive asked — new prefix test in handleNextServeHTTP; Desired names URL path under `/crowdsec-internal/challenge/`
  Decision: resolved — `req.URL.Path` (inbound request). Query stays off the check.
  By: explore

- Q: Exact prefix match, including `/crowdsec-internal/challenge` with no extra segment?
  Rank: additive asked — new prefix constant; Desired says under `/crowdsec-internal/challenge/`
  Decision: assumed — `strings.HasPrefix(path, "/crowdsec-internal/challenge/")` (trailing slash), same as upstream PR 403 point 4 and the official `/*`. The bare path without a slash is not terminated here.
  By: explore

- Q: Does passthrough-as-allow (500/unreachable with `*Block` false) 404 the prefix in the same place as HTTP 200?
  Rank: additive asked — same nil-error branch; Problem names that leak
  Decision: assumed — yes; both return nil from `appsecQuery` today and share the new 404.
  By: explore

- Q: Should dest grow an OpenSpec catalog so the ticket can “update the spec”?
  Rank: additive incidental — dest has no spec catalog or callers; bootstrapping would add a unit; Desired names an update, not a new catalog
  Decision: assumed — no. README is the operator contract on dest. Do not bootstrap `openspec/`.
  By: explore
  Pass: openspec-catalog.md
