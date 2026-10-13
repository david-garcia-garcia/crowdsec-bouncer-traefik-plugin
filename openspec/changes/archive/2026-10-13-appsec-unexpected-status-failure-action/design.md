## Context

See proposal.md Why. Query already maps 500 and unreachable through `resultForFailureAction`. `interpretAppsecBody` returns `appsecQuery statusCode:<n>` for any other non-200 without a parseable non-empty JSON action. `applyAppsecServeHTTP` bans every Query error except `ErrFailureCaptcha` and `ErrClientDisconnected`. Dest reproduce: passthrough on 401 still yields `appsecQuery statusCode:401`.

Community PR 403 point 2 puts 401 and unexpected on the same `crowdsecAppsecFailureBlock` bool as 500. This fork already has the enum and JSON parse on any status; do not copy that switch.

## Goals / Non-Goals

**Goals:**

- Reuse `resultForFailureAction` for 401 and unexpected statuses after JSON parse.
- Keep 403 empty/invalid JSON fail-closed.
- Error-log unexpected failure with slog `statusCode` attr.

**Non-Goals:**

- Changing 500, 502/503/504, disconnect, or body-limit paths.
- Changing `applyAppsecServeHTTP`.
- Copying community PR 403's bool/default branch.

## Decisions

- Apply FailureAction in Query after `interpretAppsecBody`, not before body parse. Alternative: 401 next to 500 before parse — rejected because a parseable JSON action on 401 must stay a verdict.
- Treat listener 403 without a non-empty action as fail-closed (existing error). Alternative: FailureAction on every non-200 — rejected; challenge protocol fail-closes empty/invalid 403 (`devstate` deviations).
- Log `c.log.Error("appsecQuery:failure", "statusCode", statusCode)`. Alternative: `fmt.Sprintf` like PR 403 — rejected; this fork uses slog attrs (`std_go_logger_debug-attrs`). Do not change 500's Info line.
- Regression in `pkg/appsec/zzz_failure_action_test.go` covering 401 and one other unexpected status (418) for passthrough/ban/captcha. Must fail on dest.

## Risks / Trade-offs

- [Passthrough on 401 lets traffic through when AppSec rejects the bouncer key] → that is the protocol fallback; default FailureAction remains ban.
- [403 empty stays ban while 401 passthrough] → matches the protocol table; documented as a reshape of the ticket letter.
- [500 still logs Info without status] → out of scope; 401/unexpected get Error plus `statusCode`.
