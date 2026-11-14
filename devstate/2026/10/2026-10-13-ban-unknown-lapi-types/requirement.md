# Requirement
IssueKey: 2026-10-13-ban-unknown-lapi-types

## Problem
A CrowdSec LAPI or blocklist decision whose type is neither `ban` nor `captcha` (including `challenge`, which has nothing to render) is skipped at ingest. Stream, live, and none then allow the IP. CrowdSec's challenge protocol and lua-cs-bouncer fail closed to ban for unsupported types.

## Current (code)
- `pkg/decisionscope/lookup.go` `RemediationValue` maps only `ban` to `BannedValue` and `captcha` to `CaptchaValue`; any other type returns empty.
- `pkg/lapi/client_decisions.go` `streamPutItem`: empty kind logs `handleStreamCache:unknownType` at Debug and returns `ok=false`, so stream does not store the IP.
- `pkg/lapi/client_stream.go` Range `new`: empty `RemediationValue` skips the Range upsert (same skip, not `streamPutItem`).
- `pkg/lapi/client_decisions.go` `strongestLiveDecision`: skips types whose `RemediationValue` is not ban or captcha.
- `pkg/lapi/client_decisions.go` `queryLiveDecisions`: nil pick or empty kind returns `NoBannedValue`, so live/none allow.
- `pkg/logger/logger.go` `Trace` is the TRACE helper (`slog` has no Trace method). The unknown-type line is Debug today.

## Desired
- Stream, live, and none store and apply a decision whose type is neither ban nor captcha (`challenge`, `allow`, anything else) as a ban.
- Empty decision lists stay no-remediation.
- Log the unknown type at TRACE with `logger.Trace` and stem `handleStreamCache:unknownType` (not Info, not Debug).
- Do not change `RemediationValue`'s empty default. Origin remap and other callers use empty as "not a remediation code".
- Fail closed only at LAPI ingest (`streamPutItem` and the live query path).
- Regression tests must fail on master if an unknown type is skipped or allowed.
- Delivery card must mention upstream https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 point 1. Do not copy that patch (it edits root `bouncer.go`, which master does not have).

## Affected
- `pkg/lapi/client_decisions.go` (`streamPutItem`, `queryLiveDecisions`, `strongestLiveDecision`)
- `pkg/lapi/client_stream.go` (Range kind mapping — see Tensions)
- `pkg/lapi` tests for stream put, stream apply, and live query
- `openspec/specs/core_plugin_lapi_origin-based-decision-remap/spec.md` ("An unknown type SHALL stay empty (skip store)")
- `openspec/specs/core_plugin_decisions_scopes/spec.md` ("Unknown types SHALL be ignored")
- `knowledge/devdocs/core_plugin_lapi_stream-apply.md`
- `knowledge/devdocs/core_plugin_lapi_origin-based-decision-remap.md`

## Out of scope
- AppSec challenge relay
- Metrics
- Captcha
- Workflow files (`.github/workflows`)
- Closed PR 193 and its branch
- Copying upstream PR 403's patch
- Changing `RemediationValue`'s default empty return
- Hardcoding `github.com/maxlerebourg/...` as a checkout path
- Copying vendor packages onto GOPATH

## Unknowns
- Whether stream Range upserts (not `streamPutItem`) must also map unknown types to ban. Desired says stream; ingest list names only `streamPutItem` and live.
- Whether live/none with only unknown types must cache a ban slot, or only return ban on that query.
- Exact TRACE log site for live (today the stem exists only on `streamPutItem`).
- Whether `type=allow` as ban at ingest is intended to override existing whitelist debt (named in Desired).

## Tensions
- Ticket: fail closed only at `streamPutItem` and live vs Range ingest also skipping unknown types.
- Ticket: store `allow` as ban vs `knowledge/debt/2026-09-19-multiple-decisions-per-cache-key.md` (allow as whitelist over a ban).
- Spec `core_plugin_lapi_origin-based-decision-remap`: unknown type stays empty (skip store) vs this ticket.
- Spec `core_plugin_decisions_scopes`: unknown types SHALL be ignored vs this ticket.
- Current unknown-type log is Debug; ticket wants TRACE.
