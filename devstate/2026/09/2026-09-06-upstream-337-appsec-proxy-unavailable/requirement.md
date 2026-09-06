# Requirement
IssueKey: 2026-09-06-upstream-337-appsec-proxy-unavailable

## Problem
Upstream #337: when Traefik reaches AppSec through an L7 proxy and CrowdSec is down, the proxy returns HTTP 502/503/504. v1.6.0 treated those as a generic non-200 AppSec response and banned (403) even when the operator set passthrough (`crowdsecAppsecUnreachableBlock: false`). Assessment on `master`: behavior is likely fixed via `isReverseProxyError` + `crowdsecAppsecFailureAction`, but no test proves passthrough on HTTP 502/503/504.

## Current (code)
- `pkg/appsec/query.go:98-101` — transport error or `isReverseProxyError(status)` calls `resultForFailureAction(pol.FailureAction, "appsecQuery:unreachable")`.
- `pkg/appsec/client.go:99-103` — `isReverseProxyError` is true for 502, 503, 504.
- `pkg/appsec/query.go:42-57` — `resultForFailureAction` maps `passthrough` to allow, `ban` to error, `captcha` to `ErrFailureCaptcha`.
- `pkg/configuration/configuration.go` — public key is `crowdsecAppsecFailureAction` (`passthrough` | `ban` | `captcha`); legacy `crowdsecAppsecUnreachableBlock` removed.
- `openspec/specs/core_plugin_appsec_failure-action/spec.md:18-27` — spec requires 502/503/504 unreachable + passthrough proceeds to `next`.
- `pkg/appsec/failure_action_test.go:44-65` — `Test_appsecQuery_failureActionOnUnreachable` covers transport unreachable only (closed server), not HTTP 502/503/504 responses.
- `pkg/appsec/failure_action_test.go:13-42` — `Test_appsecQuery_failureActionOn500` covers HTTP 500 failure action paths.
- `tests/e2e/mock/scenarios/appsec/run.sh:30-31` — e2e asserts 502 with default `ban` (403); no passthrough case for proxy errors.

## Desired
Add tests (unit and/or e2e) that prove when AppSec returns HTTP 502, 503, or 504, `crowdsecAppsecFailureAction: passthrough` allows the request (same as transport unreachable). Do not change product behavior unless a test cannot be honest without a one-line correctness fix.

## Affected
- `pkg/appsec/failure_action_test.go` (primary: table or cases for 502/503/504 × failure actions)
- optionally `tests/e2e/mock/scenarios/appsec/run.sh` (passthrough on proxy error status)

## Out of scope
- Reintroducing `crowdsecAppsecUnreachableBlock` or changing failure-action semantics beyond upstream #337.
- Broader AppSec query hardening (body limits, header forwarding) unless required for honest tests.
- Changing default `ban` behavior for proxy errors (already covered by e2e 502 ban case).

## Unknowns
- Whether e2e mock can configure `crowdsecAppsecFailureAction: passthrough` per scenario without new fixture wiring.

## Tensions
- Assessment says `affected: no` / `present-fixed-unproven` vs upstream reporter’s live 403 on v1.6.0 — ticket is regression-proofing, not a confirmed live bug on `master`.
- Unit httptest vs e2e: assessment cites both proof gaps; scope is tests only per `recommended-action: add-tests`.
