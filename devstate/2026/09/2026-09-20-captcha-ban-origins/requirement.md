# Requirement
IssueKey: 2026-09-20-captcha-ban-origins

## Problem
CrowdSec delivers many blocklist decisions as type `ban` (CAPI community blocklist, console-subscribed lists). Operators cannot change that type in console or `profiles.yaml` for those sources. Visitors on shared lists get a hard ban with no captcha path unless the bouncer remaps selected origins at store time. Upstream solved this with `CaptchaBanOrigins` in https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/369; this fork names the knob `BanToCaptchaOrigins` and matches `MetricsOrigin` strings (`lists` vs `lists:<name>`).

## Current (code)
- `BanToCaptchaOrigins` config field: not found. `pkg/configuration/configuration.go`
- Stream Ip/header apply maps LAPI `type` via `RemediationValue` only (ban → `t`, captcha → `c`). `pkg/lapi/client_decisions.go` (`streamPutItem`)
- Stream Range apply uses the same `RemediationValue(decision.Type)` before `KindOriginString`. `pkg/lapi/client_stream.go`
- Live/none LAPI queries map `picked.Type` through `RemediationValue` only; cached kinds use that letter. `pkg/lapi/client_decisions.go` (`queryLiveDecisions`, `cacheLiveScope`, `memoLive`)
- Stored origin for metrics and decisions uses `MetricsOrigin(origin, scenario)` (`lists` → `lists:<scenario>`). `pkg/lapi/client_metrics.go`
- Request path: captcha kind without a configured provider falls back to ban rendering. `pkg/bouncer/bouncer.go` (`handleRemediationServeHTTP`)
- Usage-metrics origin vocabulary for CAPI / `lists:XXX`: documented in `knowledge/research/ext_crowdsec_lapi_usage-metrics/notes.md` and `knowledge/devdocs/core_plugin_lapi_usage-metrics.md`

## Desired
- Add `BanToCaptchaOrigins []string` (empty default → no-op). When a stream decision has LAPI type `ban` and `MetricsOrigin(origin, scenario)` matches an entry, store captcha remediation (`c`) instead of ban (`t`) for Ip, header-scope, and Range paths — same storage model as today (kind letter + origin on the decision store / range-index).
- Matching rules: exact string on the metrics origin after `MetricsOrigin`; entry `lists` matches any `lists:<name>`; entry `lists:<name>` matches only that list. Unlisted origins stay ban.
- Align behavior with upstream https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/369 except for the per-list origin differentiation above.
- Without captcha provider, stored captcha still renders as ban (existing fallback).

## Affected
- `pkg/configuration/configuration.go` (config surface + validation if needed)
- Plugin wiring that passes config into LAPI client (explore/propose to name paths)
- `pkg/lapi/client_decisions.go`, `pkg/lapi/client_stream.go` (stream apply; likely shared helper)
- Possibly `pkg/lapi/client_live.go` / live cache if live/none must mirror stream remapping
- OpenSpec config + decision-scope specs; devdocs for operators
- Tests for origin matching (`lists`, `lists:foo`, CAPI, unlisted)

## Out of scope
- Changing CrowdSec console, CAPI, or LAPI to emit `captcha` type for blocklists
- Traefik plugin reload / ticker-stop behavior (not requested)
- AppSec or failure-action captcha paths (LAPI decision origins only)
- Metrics label changes beyond what stored remediation already drives

## Unknowns
- Whether live/none mode must remap ban→captcha on LAPI query/cache the same way as stream apply (ticket emphasizes stream blocklists; explore should confirm upstream #369 scope).
- Whether config validation should reject unknown origin tokens or accept any string (upstream pattern TBD in propose).

## Tensions
- Upstream remaps on raw LAPI `origin` at apply time; this fork must match on post-`MetricsOrigin` strings so `lists:firehol_level1` differs from `lists:other`.
- Ticket asks to adopt upstream PR layout; dest already interns/packs origins in `decisionstore` — implementation stays on this fork’s stream write paths, not upstream file paths.
