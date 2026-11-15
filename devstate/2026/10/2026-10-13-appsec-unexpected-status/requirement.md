# Requirement
IssueKey: 2026-10-13-appsec-unexpected-status

# AppSec 401 and unexpected statuses follow the failure action

CrowdSec's challenge protocol: HTTP 401, 500, or an unexpected AppSec status uses the component's configured AppSec failure behaviour. 502, 503, and 504 count as unreachable.

This fork already applies `bouncerAppsecFailureAction` (passthrough | ban | captcha) to HTTP 500, transport failure, and listener 502/503/504. `Test_appsecQuery_failureActionOnServerError` covers those four statuses.

A bare 401 (and any other unexpected status that is not 200, not 502/503/504, and not a parseable JSON action) becomes `appsecQuery statusCode:<n>` from `interpretAppsecBody`. `applyAppsecServeHTTP` treats that error as a ban regardless of `bouncerAppsecFailureAction`, and logs it at Debug. A throwaway test showed passthrough on 401 returns `appsecQuery statusCode:401`.

Current spec `openspec/specs/core_plugin_appsec_failure-action` says legacy empty/non-JSON non-200 (other than 500/502/503/504) SHALL still ban. That sentence conflicts with the protocol. Update the spec so 401 and other unexpected listener statuses follow `bouncerAppsecFailureAction` the same way 500 does. 502/503/504 stay unreachable. Parseable JSON with a non-empty action (allow, ban, captcha, challenge, other) is not a failure status.

Desired: passthrough on 401 allows the request (Query returns allow, bouncer calls next). ban on 401 forbids. captcha on 401 is ErrFailureCaptcha / the captcha client. Log the failure at Error with the status code (this fork uses slog; match existing Error lines, do not invent a new logger).

Out of scope: changing 500/502/503/504 behavior. Client disconnect. Body limits.

Add a regression test that fails on dest when 401 ignores passthrough. Run tests on this machine.

Upstream (must appear on every delivery card / PR body): https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 (fixes https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/402, point 2). Say this fork's gap versus that PR. Do not claim we copied their patch.

## Current (code)

- `pkg/appsec/query.go` `Query`: HTTP 500 calls `resultForFailureAction` and logs `appsecQuery:failure` at Info. Transport failure and listener 502/503/504 call `resultForFailureAction` and log `appsecQuery:unreachable` at Error. Other statuses fall through to `interpretAppsecBody`.
- `pkg/appsec/query.go` `interpretAppsecBody`: parseable JSON with a non-empty `action` is returned as a verdict. HTTP 200 without that envelope is allow. Any other status returns `appsecQuery statusCode:<n>` and does not consult `Policy.FailureAction`.
- `pkg/bouncer/bouncer.go` `applyAppsecServeHTTP`: `ErrFailureCaptcha` serves the captcha client. Any other Query error (including `appsecQuery statusCode:401`) is a ban with `ReasonAPPSEC`, logged at Debug (`applyAppsecServeHTTP`).
- `pkg/appsec/zzz_failure_action_test.go` `Test_appsecQuery_failureActionOnServerError`: covers 500/502/503/504 only. No 401 case.
- `openspec/specs/core_plugin_appsec_failure-action/spec.md`: "Legacy empty/non-JSON non-200 (other than 500/502/503/504) SHALL still ban."
- `knowledge/research/ext_crowdsec_appsec_protocol/notes.md`: CrowdSec challenge protocol maps 401, 500, and unexpected status to `APPSEC_FAILURE_ACTION`. 502/503/504 are not that table. 403 with a JSON action is a verdict; 403 with empty or invalid JSON is fail-closed ban in the challenge protocol.

## Desired

- A bare HTTP 401, and any other unexpected listener status that is not 200, not 502/503/504, and not a parseable JSON action, SHALL apply `bouncerAppsecFailureAction` the same way HTTP 500 already does.
- `passthrough` on 401: Query returns allow; the bouncer calls next.
- `ban` on 401: Query forbids (`appsecQuery statusCode:401`).
- `captcha` on 401: Query returns `ErrFailureCaptcha`; the bouncer serves the captcha client.
- Log that failure at Error with the status code, using this package's existing slog (`log.Error` plus attrs). Do not add a logger.
- 502/503/504 stay unreachable. Parseable JSON with a non-empty action (allow, ban, captcha, challenge, other) is not a failure status.
- Update `openspec/specs/core_plugin_appsec_failure-action` so the legacy-ban sentence no longer contradicts the protocol.
- Regression test that fails on dest when 401 ignores passthrough.
- Delivery card and PR body name upstream https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 (fixes https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/402, point 2) and this fork's gap versus that PR. Do not claim we copied their patch.

## Affected

- `pkg/appsec/query.go` (`interpretAppsecBody` / `Query`)
- `pkg/bouncer/bouncer.go` (`applyAppsecServeHTTP` only if the Query error path still hides the failure)
- `pkg/appsec/zzz_failure_action_test.go` (or a sibling 401 regression)
- `openspec/specs/core_plugin_appsec_failure-action/spec.md`

## Out of scope

- Changing HTTP 500, 502, 503, or 504 behavior (including 500's Info log).
- Client disconnect (`ErrClientDisconnected`).
- Body limits / oversized AppSec bodies.
- Copying upstream PR 403's patch.

## Unknowns

- Whether CrowdSec's live challenge-protocol table still matches `knowledge/research/ext_crowdsec_appsec_protocol` (fetched 2026-09-05).
- What upstream PR 403 actually changes, and the exact gap this fork still has after our own 500/unreachable work.
- Whether HTTP 403 with empty or invalid JSON is an "unexpected status" (ticket) or a fail-closed ban (challenge protocol).
- The exact slog message and attrs for the new Error line (`appsecQuery:failure` plus `statusCode`, or another existing key).

## Tensions

- Ticket vs spec: `core_plugin_appsec_failure-action` still requires legacy empty/non-JSON non-200 (other than 500/502/503/504) to ban; the ticket says that sentence is wrong.
- Ticket vs challenge protocol: the ticket folds every non-200, non-502/503/504, non-parseable-action status into FailureAction (so a bare 403 would passthrough when configured). Challenge protocol fail-closes empty/invalid-JSON 403 to ban.
- Ticket vs current 500 logging: 500 already uses FailureAction but logs Info `appsecQuery:failure` with no status attr. The ticket wants Error plus status for 401/unexpected and forbids changing 500.
