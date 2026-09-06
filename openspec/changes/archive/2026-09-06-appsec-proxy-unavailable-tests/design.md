## Context

See proposal.md Why. `Client.Query` already routes `isReverseProxyError` (HTTP 502/503/504) through `resultForFailureAction`. Unit tests cover HTTP 500 and transport unreachable (closed httptest). Mock e2e covers 502 with default `ban` only. Explore measured passthrough/ban/captcha on 502/503/504 on current HEAD.

## Goals / Non-Goals

**Goals:**
- Committed unit proof that HTTP 502, 503, and 504 honor the three failure actions.
- Spec scenarios that name those HTTP statuses.

**Non-Goals:**
- Product behavior change.
- New e2e scenario or mocklapi 503/504 paths.
- Bouncer-level duplicate of 500 passthrough→`next`.
- Draining the reverse-proxy response body (follow-up on `issues.md`).

## Decisions

- Prove at `pkg/appsec.Query` (classification owner), table-driven in `failure_action_test.go`, mirroring `Test_appsecQuery_failureActionOn500`. Alternative: e2e passthrough scenario — rejected; existing mock YAML is locked to `ban` and Bound the ask.
- httptest returns the status; reuse `newQueryClient`. Alternative: inject a fake RoundTripper — unnecessary when httptest already works for 500.
- Fold onto `core_plugin_appsec_failure-action`. Alternative: new spec leaf — rejected; this is a small adjustment to the existing unreachable contract.

## Risks / Trade-offs

- [Tests pass while bouncer wiring drifts] → Accept: bouncer already asserts 500 passthrough calls `next`; Query is the status classifier.
- [E2E still silent on 503/504 passthrough] → Accept: unit table covers all three statuses; e2e keeps default-ban 502.
