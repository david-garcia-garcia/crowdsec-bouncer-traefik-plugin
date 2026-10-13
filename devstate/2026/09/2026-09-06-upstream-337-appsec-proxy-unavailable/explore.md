# Explore
IssueKey: 2026-09-06-upstream-337-appsec-proxy-unavailable

## Concepts

Upstream #337: an L7 proxy in front of AppSec (Envoy in the report) answers HTTP 502/503/504 when CrowdSec is down. On v1.6.0 those statuses fell through `interpretAppsecBody` as generic non-200 (`appsecQuery statusCode:503`) and the bouncer banned, ignoring `crowdsecAppsecUnreachableBlock: false`.

On this tree the public knob is `crowdsecAppsecFailureAction` (`passthrough` | `ban` | `captcha`). `Client.Query` classifies transport errors and `isReverseProxyError` (502/503/504) as unreachable and runs `resultForFailureAction`. HTTP 500 is a separate log (`appsecQuery:failure`) with the same action mapper.

```
AppSec Query
     │
     ├─ transport error ────────────────────────┐
     ├─ HTTP 502 / 503 / 504  (proxy down) ─────┤── unreachable → resultForFailureAction
     ├─ HTTP 500  (AppSec internal) ────────────┘── failure     → resultForFailureAction
     ├─ HTTP 200 / structured JSON action ───────── verdict (not a failure action)
     └─ other non-200 ──────────────────────────── generic ban (legacy)
```

Owner of the classification is `pkg/appsec` (`isReverseProxyError` in `client.go`, `Query` in `query.go`). The bouncer only consumes allow / error / `ErrFailureCaptcha`. Client IP is already on `clientRequest`; this change does not reconstruct identity.

Existing coverage:

- Unit: transport unreachable (closed httptest) and HTTP 500, all three actions (`pkg/appsec/failure_action_test.go`). Passes.
- Bouncer: HTTP 500 passthrough calls `next` (`pkg/bouncer/bouncer_test.go`).
- E2E mock: `/foo/502` with default `ban` → 403 (`tests/e2e/mock/scenarios/appsec/`). Scenario YAML is locked to `crowdsecAppsecFailureAction: ban`. Mocklapi returns 502 when the forwarded URI contains `"502"`; no 503/504 paths.

Throwaway httptest (not committed) on current HEAD: HTTP 502, 503, and 504 each honor passthrough→allow, ban→error, captcha→`ErrFailureCaptcha`. Behavior is present; the gap is committed proof.

Usage packet `knowledge/devdocs/core_plugin_appsec.md` already says 500, unreachable, and unreadable body share `crowdsecAppsecFailureAction`. Research `ext_crowdsec_bouncers_failure-action/` and `ext_crowdsec_appsec_protocol/` already document Traefik treating 502/503/504 as unreachable. No new research write. Spec leaf `core_plugin_appsec_failure-action` already requires 502/503/504 as unreachable and passthrough→`next`. Propose folds a named HTTP-status scenario onto that leaf rather than a new spec.

## Decisions

- Add-tests only. Do not change `Query` unless a committed test cannot be honest. Measured: current code already matches the ticket.
- Prove the gap in `pkg/appsec/failure_action_test.go` with a table of HTTP 502, 503, and 504 × passthrough / ban / captcha, mirroring `Test_appsecQuery_failureActionOn500`. That is the classification owner.
- Do not add a second mock e2e scenario or a second middleware just to set `passthrough`. E2E already proves default ban on 502. 503/504 stay unit-only.
- Do not add a parallel bouncer `handleNextServeHTTP` case for 502; 500 already proves passthrough reaches `next`.
- Do not reintroduce `crowdsecAppsecUnreachableBlock`.
- Do not fix the reverse-proxy response-body drain in this change (see `issues.md`).

## Open questions

- Q: Should e2e mock also assert passthrough on HTTP 502/503/504?
  Decision: assumed — no; unit tests are the proof. The existing appsec mock scenario is wired to `ban`. A passthrough case needs a new scenario or dual middleware. Bound the ask: unit table is enough; e2e keeps the default-ban 502 check.
  By: explore

- Q: Does the existing spec scenario "Unreachable passthrough" already cover HTTP 502/503/504, or do we add a named reverse-proxy scenario?
  Decision: assumed — fold a named scenario onto `core_plugin_appsec_failure-action` so the HTTP statuses are explicit (upstream #337 was specifically proxy statuses, not dial failure). Same leaf; no new spec id.
  By: explore

- Q: Who owns client address / Host for this work?
  Decision: resolved — `pkg/ip.GetRemoteIP` / `clientRequest`; this ticket does not reconstruct identity. Tests pass a literal IP into `Query` like the existing failure-action tests.
  By: explore
