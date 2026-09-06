# Requirement
IssueKey: 2026-09-05-remediation-codes-owner

## Problem

CrowdSec remediation vocabulary (`t` ban, `c` captcha, `f` none, `d` captcha-grace-done) lives on `pkg/cache` next to the string KV. Packages that decide or apply a ban import the store package to name those codes.

## Current (code)

- `pkg/cache/cache.go` defines `BannedValue = "t"`, `NoBannedValue = "f"`, `CaptchaValue = "c"`, `CaptchaDoneValue = "d"` beside store errors `CacheMiss` and `CacheUnreachable`.
- `pkg/decisionscope/lookup.go` maps LAPI types `ban`/`captcha` via `cache.BannedValue` / `cache.CaptchaValue`, prefers ban, and still uses `cache.Client` plus `cache.CacheMiss` for lookup.
- `pkg/decisionscope/rangemembership.go` classifies index lines with `cache.BannedValue` / `cache.CaptchaValue`.
- `pkg/decisionscope/range.go` imports `pkg/cache` for `Client` (range-index Get/Set), not for the code names.
- `pkg/decisionscope/lookup.go` imports `pkg/configuration` for `StreamMode` / `AloneMode` (keep).
- `pkg/captcha/captcha.go` writes and compares `cache.CaptchaDoneValue` on `{ip}_captcha` via `cache.Client`.
- `pkg/bouncer/bouncer.go` branches on `cache.NoBannedValue` / `cache.CaptchaValue` and still needs `cache.CacheMiss` / `cache.CacheUnreachable`.
- `pkg/crowdsecconnection/connection.go` and `connection_decisions.go` store `cache.NoBannedValue` through `cache.Client`.
- Tests compare against `cache.BannedValue` / `cache.CaptchaValue` / `cache.NoBannedValue` in `pkg/decisionscope/*_test.go`, `pkg/bouncer/bouncer_test.go`, `pkg/crowdsecconnection/connection_range_test.go`, `plugin_test.go`. `pkg/cache/cache_test.go` uses those consts as opaque Set/Get payloads.

## Desired

- `pkg/decisionscope` owns ban / captcha / none codes (`BannedValue`, `CaptchaValue`, `NoBannedValue`) with wire values still `t` / `c` / `f`.
- `pkg/captcha` owns grace-done (`CaptchaDoneValue`) with wire value still `d`.
- `pkg/cache` remains a string KV: Get / Set / Delete / GetMany plus `CacheMiss` / `CacheUnreachable`. No CrowdSec vocabulary.
- Call sites in bouncer, crowdsecconnection, decisionscope, captcha, and tests use the new owners. Redis and memory entries stay compatible.
- Do not invent `pkg/remediation`. Do not change cache Redis/memory behavior. Do not drop the configuration import from decisionscope. Do not split `connection.go`.

## Affected

- `pkg/cache/cache.go`, `pkg/cache/cache_test.go`
- `pkg/decisionscope/lookup.go`, `rangemembership.go`, tests
- `pkg/captcha/captcha.go`
- `pkg/bouncer/bouncer.go`, `bouncer_test.go`
- `pkg/crowdsecconnection/connection.go`, `connection_decisions.go`, `connection_range_test.go`
- `plugin_test.go`
- Usage packets `knowledge/devdocs/core_cache_client.md` and `knowledge/devdocs/core_plugin_decisionscope.md` (vocabulary owner)

## Out of scope

- Sibling tickets: `2026-09-05-split-connection-files`, `2026-09-05-split-configuration-files`, `2026-09-05-split-ip-trust`, `2026-09-05-scope-headers-identity`, `2026-09-05-decisionscope-mode-bool`, `2026-09-05-config-prepare-snapshot`
- New package `pkg/remediation`
- Cache Redis vs memory behavior, key prefixing, Get/Set/Delete/GetMany shape
- Removing `pkg/configuration` from `pkg/decisionscope`
- Splitting `pkg/crowdsecconnection/connection.go`

## Unknowns

- After the move, `pkg/cache` tests should treat `"t"`/`"c"` as opaque strings (no import of decisionscope) versus keep named consts — not stated.
- Whether `NoBannedValue` stays that identifier on decisionscope — ticket names the const, not a rename.

## Tensions

- Ticket says four packages import the KV store just to name a ban. Code: `pkg/decisionscope`, `pkg/captcha`, `pkg/bouncer`, and `pkg/crowdsecconnection` still need `cache.Client` and/or `CacheMiss` / `CacheUnreachable` after the vocabulary moves. The gap is owner of the codes, not dropping those cache imports.
- Spec `openspec/specs/core_plugin_decisions_scopes/spec.md` says ban/captcha remediations stay current; it does not name `pkg/cache` as owner. Spec `openspec/specs/core_plugin_lapi_failure-action/spec.md` cites `BannedValue` as today’s ban outcome, not the package that defines the string.
