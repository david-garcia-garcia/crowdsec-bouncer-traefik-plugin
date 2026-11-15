# Explore

## Concepts

- **Bouncer ServeHTTP** (`pkg/bouncer/bouncer.go`): trusted IPs skip to `next`; then LAPI; then `serveAppSec`; else `next`.
- **serveAppSec** (`pkg/bouncer/bouncer.go`): captcha action rule → `applyCaptchaRuleServeHTTP`; SkipAppsec → false; else `subscribeAppSec && applyAppsecServeHTTP`. False means the caller calls `next`.
- **applyAppsecServeHTTP** (`pkg/bouncer/bouncer.go`): Query AppSec or apply failure action. True = wrote ban/relay/captcha-failure/disconnect. False = allow, empty, unpublished passthrough.
- **applyCaptchaRuleServeHTTP** (`pkg/bouncer/bouncer.go`): runs AppSec first; if AppSec did not write, serves the plugin captcha gate. A 404 inside `applyAppsecServeHTTP` on allow would steal this fallthrough.
- **AppSec Query** (`pkg/appsec/query.go`): HTTP 200 / allow JSON → `ActionAllow`. Failure passthrough also returns allow.
- **Call sites** of `applyAppsecServeHTTP`: 2 production (`applyCaptchaRuleServeHTTP`, `serveAppSec`). Roots searched: `pkg/**/*.go` (`applyAppsecServeHTTP|serveAppSec`). `serveAppSec` itself: 1 production (`ServeHTTP`) plus test helper `continueAfterLAPIForTest`.
- **Reproduce:** throwaway `pkg/bouncer/zzz_explore_repro_test.go` (deleted after). AppSec HTTP 200 `{"action":"allow"}` on `GET /crowdsec-internal/challenge/custom.js` → status 200, `nextCalled=true`. Unpublished AppSec + passthrough on the same path → status 200, `nextCalled=true`. Desired is 404 and `next` not called.
- **Outside facts:** `knowledge/research/ext_crowdsec_appsec_bot-detection/` (forward `/crowdsec-internal/challenge/*` unmodified, never to origin). `knowledge/research/ext_crowdsec_appsec_protocol/` (HTTP 200 = allow). Upstream https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 point 4 (AppSec allows `custom.js` → origin 200 on their main; they 404). Not re-measured against a live CrowdSec engine on this machine.
- **Usage:** `knowledge/devdocs/core_plugin_appsec.md` already says do not send the prefix to origin.

```
ServeHTTP
  trusted? → next
  serveLAPI wrote? → return
  serveAppSec
    captcha rule? → AppSec then plugin gate
    SkipAppsec? → false
    applyAppsecServeHTTP
      wrote ban/relay? → true
      allow / passthrough? → false  ← leak on /crowdsec-internal/challenge/*
  next  ← origin
```

## Decisions

- Seam: `serveAppSec`, after AppSec did not write and there is no captcha-rule fallthrough, when `subscribeAppSec && !SkipAppsec` and `URL.Path` has prefix `/crowdsec-internal/challenge/`: write 404 and return true. `ServeHTTP` then does not call `next`.
- Keep `applyAppsecServeHTTP` as the writer of relay/ban/captcha-failure. Do not 404 there, so a matched captcha action rule still serves the plugin gate.
- Paths outside the prefix stay allow → `next`. Trusted IPs stay the existing skip in `ServeHTTP`.
- Live contract: `openspec/specs/core_plugin_appsec_bot-detection/spec.md` (MODIFIED: allow/empty 200 must not call `next` on the prefix). Also fold a carve-out into `openspec/specs/core_plugin_appsec_failure-action/spec.md` (passthrough continues to `next` except this prefix when AppSec was in use). README bot-detection sentence.
- Rejected: copy maxlerebourg PR 403 patch (different tree: root `bouncer.go`; ticket forbids copy).
- Rejected: 404 inside `applyAppsecServeHTTP` (would block captcha-rule fallthrough).
- Rejected: new trusted-IP exception (ticket: reuse the existing skip).

## Open questions

- Q: Does the prefix include exact `/crowdsec-internal/challenge` with no trailing slash?
  Rank: additive asked — new membership test this change adds; Desired names `/crowdsec-internal/challenge/`
  Decision: assumed — `strings.HasPrefix(path, "/crowdsec-internal/challenge/")` as written. The regression path is `custom.js` under that slash.
  By: explore

- Q: Where does 404 run so a captcha action rule still writes the plugin gate?
  Rank: bounded asked — existing `applyAppsecServeHTTP` has 2 production callers in `pkg/bouncer`; Desired says captcha envelope still written as today
  Decision: resolved — 404 in `serveAppSec` after the captcha-rule branch, not inside `applyAppsecServeHTTP`.
  By: explore

- Q: Does SkipAppsec on a challenge path 404 or call `next`?
  Rank: additive asked — Desired says "when AppSec is in use for this request"
  Decision: assumed — SkipAppsec is not AppSec in use; still `next`. No extra skip-rule exception.
  By: explore

- Q: Which 404 helper?
  Rank: additive asked — Desired says respond 404
  Decision: assumed — `http.NotFound(rw, req.Request)` (stdlib 404 + Not Found body).
  By: explore

- Q: Who owns client trust for this path?
  Rank: additive asked — identity already chosen before AppSec
  Decision: resolved — reuse `trustedClients.Checker` skip in `ServeHTTP`; do not re-derive trust here.
  By: explore
