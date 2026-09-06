# Requirement
IssueKey: 2026-09-06-origin-for-range-decisions

## Problem
Range-only cache hits leave usage-metrics `dropped.origin` empty. Ip and header-scope values already store `t`/`c` plus U+001F plus `MetricsOrigin`. Stream Range upserts store the letter only, so lookup cannot report origin.

## Current (code)
- Stream Range apply writes `rangeUpserts[cidr] = RemediationValue(type)` (letter) in `pkg/crowdsecconnection/connection_stream.go`. Gauge origin is already set via `rememberActiveDecision(..., MetricsOrigin(...), cidr)` on the same path.
- Ip/header stream store uses `cache.RemediationWithOrigin(value, MetricsOrigin(...))` in `pkg/crowdsecconnection/connection_decisions.go`.
- `range-index` lines are `cidr=remediation`. `parseIndexLine` in `pkg/decisionscope/range.go` splits on the first `=`. `upsertIndexCIDR` writes the remediation suffix unchanged. `IsActiveRemediation` already ignores origin suffix.
- `RangeMembership` in `pkg/decisionscope/rangemembership.go` is two boolean `iplookup.Helper`s. `MembershipFromIndex` classifies by `RemediationKind`. `Remediation` returns `cache.BannedValue` or `cache.CaptchaValue` only. `Helper.IsContained` in `pkg/iplookup/iplookup.go` returns `(bool, prefixLen)` — no payload.
- `LookupCachedRemediation` in `pkg/decisionscope/lookup.go` documents empty origin for Range-only. It returns `RemediationKind` plus `RemediationOrigin` of the winning merged string. `PreferRemediation` already keeps a ban’s suffix.
- Spec `openspec/specs/core_plugin_lapi_usage-metrics/spec.md`: Range-only cache hits with no stored origin MAY omit `origin`.
- Spec `openspec/specs/core_plugin_decisions_scopes/spec.md`: Ip or header-scope MAY carry suffix; does not say the blob may. Usage packet `knowledge/devdocs/core_plugin_lapi_usage-metrics.md` and `knowledge/devdocs/core_plugin_decisionscope.md` say range-index stays letter-only.

## Desired
- At stream Range apply, upsert `RemediationWithOrigin(letter, MetricsOrigin(origin, scenario))` into the same `range-index` blob. Bare `cidr=t` must still match.
- `MembershipFromIndex` / `Remediation` return the suffixed string of the winning CIDR (ban over captcha). If several bans contain the IP, pick one rule and test it (Helper stays boolean, no payload).
- `LookupCachedRemediation` Range-only origin matches Ip/header (`t`/`c` + U+001F + MetricsOrigin).
- Redis stays one `range-index` key. Do not add per-CIDR keys or per-host keys. Leave `rememberActiveDecision` as-is.
- Specs: Range-only origin on `core_plugin_lapi_usage-metrics`; blob MAY carry suffix on `core_plugin_decisions_scopes`. Update usage-packet gotchas that say range-index stays letter-only.
- Tests: blob round-trip suffix; Range-only lookup origin; old letter-only line still bans.

## Affected
- `pkg/crowdsecconnection/connection_stream.go` (Range upsert value)
- `pkg/decisionscope/rangemembership.go` (return winning suffix)
- `pkg/decisionscope/lookup.go` (Range-only origin via existing Prefer/Origin split)
- `pkg/decisionscope/range.go` (blob already round-trips suffix if given; tests)
- `openspec/specs/core_plugin_lapi_usage-metrics/spec.md`
- `openspec/specs/core_plugin_decisions_scopes/spec.md`
- `knowledge/devdocs/core_plugin_lapi_usage-metrics.md`
- `knowledge/devdocs/core_plugin_decisionscope.md`

## Out of scope
- Changing `rememberActiveDecision` / `active_decisions` gauge
- Per-CIDR Redis keys or expanding a CIDR into host keys
- Changing `iplookup.Helper` to carry payload
- Public config / Traefik wiring
- Live/none Range path (those skip `range-index` and use LAPI `?ip=`)

## Unknowns
- Which ban CIDR is chosen when several containing bans hit (ticket: pick one rule and test it; Helper has no payload).

## Tensions
- Archived metrics design (`openspec/changes/archive/2026-09-05-align-lapi-usage-metrics/design.md`) deliberately omitted Range origin so membership could stay two boolean sets. This ticket reverses that for origin on Range-only drops, without adding Helper payload.
- `core_plugin_lapi_usage-metrics` currently allows omitting origin on Range-only hits; desired is to require it when the blob stored it.
