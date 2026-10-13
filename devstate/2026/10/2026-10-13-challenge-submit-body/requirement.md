# Requirement
IssueKey: 2026-10-13-challenge-submit-body

## Problem
The bot-detection proof is POSTed to `/crowdsec-internal/challenge/submit`. A truncated body fails AppSec validation and the visitor is challenged forever. This fork already forwards the full readable body when `appsecBodyLimit` is `0`, and the default 10MB cap is meant to be enough, but the README never says the challenge proof depends on that body.

## Current (code)
- `README.md` AppSec / bot-detection paragraph (line 155) tells operators to route `/crowdsec-internal/challenge/` through the middleware. It does not mention `/crowdsec-internal/challenge/submit` or that AppSec must receive the full POST form.
- `README.md` warning (line 530) says AppSec only receives the first 10MB by default (`appsecBodyLimit`). It does not mention the challenge proof.
- `README.md` **AppsecBodyLimit** (lines 619–620) says default `10485760` / 10MB, `0` means no limit, and only POST/PUT/PATCH/DELETE bodies are sent. It does not say the challenge proof needs that body.
- `pkg/appsec/query.go` (`newAppsecBodyRequest`): when `appsecBodyLimit > 0`, the readable body is copied through `io.LimitReader`. When the limit is `0`, `LimitReader` is skipped and `io.ReadAll` copies the whole readable body.
- `pkg/appsec/zzz_query_test.go` `Test_appsecQuery_zeroBodyLimitForwardsPost` already asserts limit `0` POSTs the full payload and restores it for origin.
- `pkg/configuration/configuration.go` default `AppsecBodyLimit` is `10485760`.
- `openspec/specs/core_plugin_appsec_client/spec.md` already requires `0` = unlimited full-body POST (not a zero-byte cap).
- `knowledge/devdocs/core_plugin_appsec.md` already says `appsecBodyLimit` `0` is unlimited.
- A positive limit smaller than the form still truncates at `query.go` `LimitReader`. No log in `pkg/appsec` names `/crowdsec-internal/challenge/submit` or that truncation.
- AppSec engine reject-truncated-proof / forever-challenge: not found in this plugin. Ticket and upstream PR 403 README assert it.

## Desired
README (the AppSec / bot-detection section and the AppsecBodyLimit key) states that `/crowdsec-internal/challenge/submit` must reach AppSec with the full form, the default 10MB is enough, a smaller positive limit cuts the proof short, and `0` means no limit (the whole body is sent). Do not write that `0` sends nothing.

Re-run `Test_appsecQuery_zeroBodyLimitForwardsPost`. Do not change that behavior. Do not add a duplicate test.

## Affected
- `README.md` (AppSec / bot-detection section; **AppsecBodyLimit** key)

## Out of scope
- Changing the limit implementation
- Metrics
- Challenge-path 404
- Copying upstream PR 403 code or its README claim that `0` sends no body

## Unknowns
- Whether CrowdSec AppSec actually rejects a truncated `/crowdsec-internal/challenge/submit` body and re-challenges forever (engine fact; not measured in this tree)
- Typical challenge-submit form size versus the 10MB default (ticket says the default is enough)

## Tensions
- Caller `DestBranch` was `main` (`origin/HEAD`). `origin/main` is the upstream-tracking mirror and does not have `appsecBodyLimit`, `Test_appsecQuery_zeroBodyLimitForwardsPost`, or this README. Those live on long-lived `origin/master`. Dest for this run is `master`.
- Upstream https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 (fixes https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/402, point 6) documents the same submit-body need, but says `crowdsecAppsecBodyLimit` `0` sends no body. That is false here: `0` is unlimited.
- Do not claim this change copies their patch. Gap versus that PR: this fork already has `0` = unlimited and the test; it only lacks the README warning that the challenge proof needs the full form.
