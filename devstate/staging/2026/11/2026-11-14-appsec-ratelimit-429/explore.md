# Explore

## Concepts

Units this change would touch:

- `applyAppsecServeHTTP` (`pkg/bouncer/bouncer.go`): AppSec leg. `case appsec.ActionBan` calls `handleBanServeHTTP` and ignores `decision.HTTPStatus`.
- `handleBanServeHTTP` (`pkg/bouncer/bouncer.go`): writes the operator ban response (metrics, remediation header, `Content-Type`, `Cache-Control`, `remediationStatusCode`, template). 10 production callers in `pkg/bouncer/bouncer.go` (LAPI, action rules, LAPI/AppSec failure actions, captcha downgrade, AppSec ban, AppSec empty challenge).
- `appsec.Response` (`pkg/appsec/query.go`): parsed envelope; `HTTPStatus` carries `http_status`. Listener 403 + JSON is a structured result. No change needed.
- Real e2e AppSec bot listener (`tests/e2e/real/config/acquis.d/appsec-bot.yaml`, port 7423): already loads a local appsec-config (`e2e/origin-scheme-grant`) mounted from `tests/e2e/real/config/appsec-configs/`.
- CrowdSec image in e2e (`tests/e2e/real/config/docker-compose.test.yml`): `crowdsecurity/crowdsec:v1.8.0`.

```
AppSec listener 403 {"action":"ban","http_status":429}
        |
   appsec.Query -> Response{Action: ban, HTTPStatus: 429}
        |
   applyAppsecServeHTTP case ActionBan
        |
   today:   handleBanServeHTTP -> WriteHeader(remediationStatusCode=403)
   desired: ban page with 429 when HTTPStatus==429, else remediationStatusCode
```

Call sites of `handleBanServeHTTP(`: 10 production, all in `pkg/bouncer/bouncer.go`. Roots searched: `pkg/**/*.go`. Only the AppSec ban site needs the AppSec status.

Reproduce: throwaway `go test ./pkg/bouncer -run TestExploreAppsecRateLimitBanStatus` on this worktree (master HEAD 3388bbca), AppSec stub answering 403 + `{"action":"ban","http_status":429}`. Result: FAIL — client status 403, header `ban:appsec`. Test file deleted.

Outside facts: `knowledge/research/ext_crowdsec_appsec_rate-limit/` (written this run). `RateLimit()` first ships in CrowdSec `v1.8.2` (not `v1.8.0`/`v1.8.1`); `pre_eval` inband only; one token bucket per (key, client IP); listener answers `blocked_http_code` (403) with `http_status` 429; the alert carries no decision and the default profiles need `Alert.Remediation`, so no LAPI ban is created. In-tree: `knowledge/research/ext_crowdsec_appsec_protocol/`.

Usage packets that will be stale after apply: `knowledge/devdocs/core_plugin_appsec.md` (ban → `handleBanServeHTTP` with remediation status), `knowledge/devdocs/core_plugin_middleware_ban-page.md` (always `remediationStatusCode`), `knowledge/devdocs/build_e2e_real.md` (bot-detection gotcha names CrowdSec `v1.8.0`).

## Decisions

- Seam: `handleBanServeHTTP` keeps its signature and delegates to a status-taking ban writer; the AppSec ban case passes a status chosen by a small `Bouncer` helper (429 when `decision.HTTPStatus == 429`, else `remediationStatusCode`). The other 9 callers do not change.
- Same template, `Content-Type`, `Cache-Control`, header `ban:appsec`, dropped metrics (`appsec`/`ban`), HEAD without body.
- Only 429 is honoured; 403, 418, 0 and missing keep `remediationStatusCode`. No `Retry-After`.
- e2e: bump `crowdsecurity/crowdsec` to `v1.8.2`; add appsec-config `e2e/rate-limit` (`RateLimit()` on `/appsec-rate-limit`) to the 7423 listener; add an AppSec-only router/middleware `/appsec-rate-limit` with the e2e ban page and remediation header; Pester case in `appsec.Tests.ps1` with its own client IP.
- Live contract: MODIFY `core_plugin_appsec_bot-detection` requirement "Structured ban keeps the operator ban template" (status exception for 429).
- Rejected: add a `status` parameter to every `handleBanServeHTTP` caller (9 callers gain a value they never vary).
- Rejected: honour any AppSec ban `http_status` (would override the operator's `bouncerRemediationStatusCode` on `SetReturnCode()`).
- Rejected: copy upstream PR 422's patch (root `bouncer.go` does not exist on master).
- Rejected: change `pkg/appsec/query.go` listener-status mapping (listener answers 403 for RateLimit).

## Open questions

- Q: Does the e2e CrowdSec image support `RateLimit()`?
  Rank: bounded asked — 1 image line in `tests/e2e/real/config/docker-compose.test.yml` plus `knowledge/devdocs/build_e2e_real.md`; Desired "Bump the CrowdSec image if v1.8.0 lacks RateLimit()"
  Decision: resolved — no; `RateLimit()` first ships in `v1.8.2` (`knowledge/research/ext_crowdsec_appsec_rate-limit/`). Bump to `crowdsecurity/crowdsec:v1.8.2`.
  By: explore
- Q: Will a `RateLimit()` block leave a LAPI ban that leaks into other e2e cases?
  Rank: additive asked — new e2e fixture this change creates; Desired "Real e2e: AppSec RateLimit() on a dedicated path"
  Decision: assumed — no LAPI decision with the default profiles (research, inferred from source); the bucket is per client IP, so the case uses its own `X-Forwarded-For` and the dedicated route is AppSec-only (`lapiEnabled=false`).
  By: explore
- Q: Which AppSec listener hosts the rate-limit config?
  Rank: additive incidental — adds one local appsec-config to the existing 7423 list; the filter only matches `/appsec-rate-limit`
  Decision: assumed — 7423 (`acquis.d/appsec-bot.yaml`), the listener that already loads local configs; 7422 keeps CRS only.
  By: explore
- Q: Name and shape of the status-taking ban writer?
  Rank: additive asked — new private method this change creates; Desired "same operator ban template … 429"
  Decision: assumed — `handleBanServeHTTP` delegates to a writer that takes the status; the AppSec ban site asks a `Bouncer` helper named for the AppSec ban status.
  By: explore
