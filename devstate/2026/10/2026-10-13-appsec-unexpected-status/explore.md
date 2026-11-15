# Explore

## Concepts

- **AppSec Query** (`pkg/appsec/query.go`): owns the listener round-trip, JSON parse (`interpretAppsecBody`), and `Policy.FailureAction`. One call site of `interpretAppsecBody` (Query).
- **Bouncer AppSec serve** (`pkg/bouncer/bouncer.go` `applyAppsecServeHTTP`): maps Query allow → next, `ErrFailureCaptcha` → captcha client, any other error → ban + Debug. Does not choose FailureAction.
- **FailureAction** (`pkg/appsec/query.go` `resultForFailureAction`): already used for HTTP 500, transport failure, 502/503/504, unreadable body, and response-body io error.
- **Live spec** `openspec/specs/core_plugin_appsec_failure-action/spec.md`: still says legacy empty/non-JSON non-200 (other than 500/502/503/504) SHALL ban.
- **Challenge protocol** (`knowledge/research/ext_crowdsec_appsec_protocol/`, live page 2026-10-13): 401 / 500 / unexpected → `APPSEC_FAILURE_ACTION`. 403 empty or invalid JSON → fail-closed ban. Parseable JSON `action` on 403 is a verdict.

```
AppSec listener status
  502/503/504 ──► unreachable ──► FailureAction     (unchanged)
  500         ──► Info failure ──► FailureAction    (unchanged)
  JSON action ──► structured verdict                (unchanged)
  200 empty   ──► allow                             (unchanged)
  403 no JSON ──► error ──► bouncer ban             (keep)
  401 / other ──► Error + FailureAction             (this change)
```

- Call sites: `interpretAppsecBody` 1 (Query). Query error ban in `applyAppsecServeHTTP` 1. Roots searched: `pkg/appsec`, `pkg/bouncer`.
- Reproduce: `go test ./pkg/appsec` throwaway `Test_repro_appsecQuery_passthroughOn401` on dest `origin/master`. Result: `decision=nil err=appsecQuery statusCode:401` under `FailureAction: passthrough`. Reproduced.
- Dest: `origin/main` is the community tree (no `bouncerAppsecFailureAction`). The subsystem lives on `origin/master`. This run retargeted dest to `master`.
- Outside facts: `ext_crowdsec_appsec_protocol`, `ext_crowdsec_appsec_bot-detection`, `ext_crowdsec_bouncers_failure-action`; live challenge protocol 2026-10-13; community PR https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 (issue 402 point 2). Usage: `core_plugin_appsec.md`, `std_go_logger_slog-output.md`, `std_go_logger_debug-attrs.md`.

## Decisions

- Apply `resultForFailureAction` in Query after `interpretAppsecBody` when the status is not 200, not 403, and not already handled as 500/unreachable, and there is no parseable non-empty JSON action.
- Log that path at Error with slog attr `statusCode` on stem `appsecQuery:failure`. Do not `Sprintf` the message. Do not change 500's Info line.
- Keep HTTP 403 with empty or invalid JSON as today's Query error (fail-closed ban). `Test_appsecQuery_emptyForbiddenErrors` stays. That is a reshape of the ticket's "any non-parseable non-200" wording; recorded in `deviations.md`.
- Keep 502/503/504 unreachable and 500's existing FailureAction path.
- Do not change `applyAppsecServeHTTP`. Passthrough returns allow so next runs; ban still errors; captcha still `ErrFailureCaptcha`.
- Regression test next to `Test_appsecQuery_failureActionOnServerError` for 401 (and one other unexpected status such as 418) with passthrough / ban / captcha. Must fail on dest.
- Fold the spec change into `core_plugin_appsec_failure-action`. Drop the legacy-ban sentence. Add 401/unexpected scenarios. Do not copy community PR 403's bool patch (`crowdsecAppsecFailureBlock` on a default branch that also swallows 500).
- Fork gap versus PR 403: they still use `crowdsecAppsecFailureBlock` and log `Error(fmt.Sprintf("appsecQuery:failure statusCode:%d"))` on every non-200/403 including 500. This fork already has the enum, slog, JSON parse on any status, and 500/unreachable FailureAction. The remaining gap is 401 and other unexpected statuses still bypassing that enum.

Rejected:

- Putting 401 next to 500 before body parse: would skip a parseable JSON action on 401, which the ticket forbids.
- Changing `applyAppsecServeHTTP` Debug-to-Error: Query owns the failure log; the bouncer Debug on a ban error already matches 500-ban.
- Copying PR 403's switch/default bool wiring: this fork already replaced those bools.

Live contract: `core_plugin_appsec_failure-action` (fold). Related mention in `core_plugin_appsec_bot-detection` (500/unreachable only; fold a 401 clause if that leaf still implies only 500).

## Open questions

- Q: Does HTTP 403 with empty or invalid JSON follow FailureAction (ticket letter) or stay fail-closed ban (challenge protocol)?
  Rank: bounded incidental — existing `interpretAppsecBody` 403 error path and `Test_appsecQuery_emptyForbiddenErrors` (1 Query call site, roots `pkg/appsec`); requirement Desired names unexpected statuses, not the 403 fail-closed rows
  Decision: assumed — keep fail-closed ban on 403 empty/invalid JSON; 401 and other unexpected statuses use FailureAction
  By: explore

- Q: Exact slog Error shape for 401/unexpected?
  Rank: additive asked — new attrs on an existing Error stem; requirement Desired "Log the failure at Error with the status code"
  Decision: assumed — `c.log.Error("appsecQuery:failure", "statusCode", statusCode)` matching existing Error stems; do not format the message
  By: explore

- Q: Who owns client identity on this path?
  Rank: additive asked — no new identity reconstruction; Query already uses `req.IPAddrString()`
  Decision: resolved — reuse `clientrequest.Request` / `GetRemoteIP`; this change does not recompute the client address
  By: explore
