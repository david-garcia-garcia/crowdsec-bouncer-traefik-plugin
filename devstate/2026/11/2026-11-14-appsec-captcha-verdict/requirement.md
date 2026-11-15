# Requirement
IssueKey: 2026-11-14-appsec-captcha-verdict

## Problem

Problem 3 of the 2026-11-14 upstream review (`ticket/source.md`): when AppSec answers with an action other than `ban` or `challenge` and no `user_body_content`, the visitor gets an empty page. The concrete case is AppSec `captcha` (`SetRemediation("captcha")`), which CrowdSec defines as an official remediation and always sends without a body. The caller asked for a sound analysis and a PR to `master` that closes it, with every related upstream issue and PR named on the delivery card.

## Current (code)

- `pkg/bouncer/bouncer.go:472-491` — `applyAppsecServeHTTP`: `ban` → ban page; `challenge` with empty body → ban page; every other non-allow action (including `captcha`) → `handleAppsecResponseServeHTTP`.
- `pkg/bouncer/bouncer.go:495-533` — `handleAppsecResponseServeHTTP`: writes `http_status` (0 → 200) and returns without a body when `user_body_content` is empty. A real AppSec `captcha` (`http_status` 403) becomes a blank 403.
- `pkg/bouncer/remediation_header.go:72-80` — `formatAppsecRelayHeader`: `captcha` → `captcha:appsec`, other actions → `{sanitized-action}:appsec`.
- `pkg/bouncer/bouncer.go:394-436` — `handleRemediationServeHTTP` / `handleCaptchaKindServeHTTP`: the configured captcha (gate cookie, solved redirect, downgrade ban) used today for LAPI captcha, captcha action rules, and AppSec failure-action captcha. Not used for an AppSec `captcha` verdict.
- `pkg/bouncer/zzz_bouncer_test.go:351-410` — `TestHandleNextServeHTTPRelaysStructuredAppsecCaptcha`, `TestHandleNextServeHTTPEmptyCaptchaBodyRelaysStatus` lock the blank relay.
- `openspec/specs/core_plugin_appsec_bot-detection/spec.md:71-84` — requirement "AppSec captcha envelope is parsed and relayed": MUST NOT use `pkg/captcha`; empty body still relays status.
- `knowledge/devdocs/core_plugin_appsec.md:30-31` — same decision in usage docs.
- `openspec/specs/core_plugin_middleware_bouncer/spec.md:229`, `README.md` header table — `captcha:appsec` documented as envelope relay.

## Desired

- An AppSec `captcha` verdict is remediated as a captcha by this bouncer, as CrowdSec's protocol says (`ban` and `captcha` are verdicts the remediation component renders from its own templates).
- An AppSec action this bouncer cannot render and that carries no body no longer produces an empty page.
- Spec and usage docs record the decision (problem 3, proposal step 3).
- The delivery card names every related upstream issue and PR.

## Affected

- `pkg/bouncer` (AppSec verdict handling, remediation header).
- `openspec/specs/core_plugin_appsec_bot-detection`, `openspec/specs/core_plugin_middleware_bouncer` (header table).
- `knowledge/devdocs/core_plugin_appsec.md`, `README.md`.

## Out of scope

- Problem 4 (AppSec `http_status` 429 kept on ban).
- Problem 2 / 7 (`/crowdsec-internal/challenge/*` termination and `bypassAppsec` exception).
- Problem 11 (startup warning for a custom captcha template without the marker).
- Changing the `http_status` 0 → 200 rule for relayed bodies.
- Separate solved-captcha state per source (LAPI vs AppSec), as lua-cs-bouncer keeps.

## Unknowns

- Runtime proof against a real CrowdSec 1.8 with a `SetRemediation("captcha")` hook (source-read only so far).
- Whether the captcha form POST, which goes through AppSec before reaching the captcha gate, gets another `captcha` verdict (depends on the operator's rule); if AppSec allows it, how the submission is validated.
- How an AppSec `captcha` interacts with a captcha action rule and with `bouncerAppsecFailureAction: captcha` on the same router.

## Tensions

- The ask reverses a deliberate spec decision (`core_plugin_appsec_bot-detection` "MUST NOT use `pkg/captcha`", made in run `2026-09-06-upstream-357-appsec-captcha-action`). That run assumed CrowdSec might send captcha HTML; CrowdSec's `GenerateResponse` never does.
- The review's minimal proposal (ban page for any bodyless action) and its open decision (serve the configured captcha, as upstream #403) both fit the ask; the caller's chat question was whether `captcha` is a real AppSec action, and it is.
