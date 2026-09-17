## Context

See proposal.md — Why. On `master`, `ActionCaptcha` is a parsed envelope value; `applyAppsecServeHTTP` special-cases only `ban` and empty-body `challenge`; other non-allow actions fall through to `handleAppsecResponseServeHTTP`. Challenge parse and relay tests exist; captcha fixtures do not. Official protocol treats captcha as a bouncer-rendered verdict; this product already relays the envelope. Bound action is add-tests.

## Goals / Non-Goals

**Goals:**
- Prove parse and relay of AppSec JSON `action: captcha` next to the existing challenge fixtures.
- Lock empty-body captcha as status relay (upstream example has no body).

**Non-Goals:**
- Changing `applyAppsecServeHTTP` / `parseResponse` unless a test cannot be honest without a one-line correctness fix.
- Routing AppSec captcha through `pkg/captcha`.
- Solved-captcha cache mode or a new config knob.
- e2e mock/pester expansion (unit tests are enough for this proof).

## Decisions

1. **Mirror challenge tests, do not share a table with challenge.** Add `Test_appsecQuery_captchaJSON` in `pkg/appsec/query_test.go` and `TestHandleNextServeHTTPRelaysStructuredAppsecCaptcha` in `pkg/bouncer/bouncer_test.go`, plus an empty-body captcha case on the bouncer. Alternative: one table-driven test for every action — rejected; keep the existing challenge tests as the sibling pattern (`skill:sbs-dev-commandments:Symmetry and consistency` at the fixture level, not a new harness).

2. **Empty-body captcha is relay, not ban.** `challenge` empty body stays a ban. Captcha empty body uses `handleAppsecResponseServeHTTP` (status from `http_status`, no body). Alternative: copy the challenge empty-body ban — rejected; upstream's example is `{"action":"captcha","http_status":403}` with no body, and explore locked current relay.

3. **Do not assert `pkg/captcha`.** Captcha HTML/cookies come from the AppSec envelope. Failure-action captcha stays out of this change.

4. **No production code unless a fixture fails honestly.** If `Query` or relay already matches the spec, tests only.

## Risks / Trade-offs

- [Official docs say captcha is bouncer-rendered] → Tests lock this fork's envelope relay; `core_plugin_appsec.md` already names that split.
- [Empty-body captcha vs empty-body challenge] → Spec scenario names the difference so a later change cannot "fix" captcha by copying the challenge ban.

## Migration Plan

None. Tests only. Rollback is revert the test commits.
