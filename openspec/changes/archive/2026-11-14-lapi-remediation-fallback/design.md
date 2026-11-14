# Design

## Context

See proposal.md (Why). Today `ingestRemediationKind` (`pkg/lapi/client_decisions.go`) maps `ban` / `captcha` through `decisionscope.RemediationValue` and every other type to `BannedValue` with TRACE `handleStreamCache:unknownType`. Its four production call sites are `streamPutItem`, `strongestLiveDecision`, and the Range New branch of `fetchAndApplyStreamDecisions` (`pkg/lapi/client_stream.go`); `queryLiveDecisions` reaches it through `strongestLiveDecision`. The Deleted paths (`streamDeleteItem` and the Range Deleted loop) never read the type, so an unknown-type Deleted row clears an Ip slot or a Range CIDR that another decision holds (reproduced in explore). Opener-only LAPI knobs are read in `lapi.New` from the connecting middleware's config (example: `LapiStreamScopes`). Store identity is `sessionFrom` (`pkg/lapi/session.go`); Client identity is `ownershipFrom` (`pkg/lapi/identity.go`).

## Goals / Non-Goals

**Goals:**
- One effective-value owner for the knob, shared by `lapi.New`, `sessionFrom`, and `ownershipFrom`.
- One ingest owner (`ingestRemediationKind`) that answers the store letter or "not stored"; every ingest site reads that answer.
- One Deleted rule shared by the Ip/header path and the Range path.
- Default deployments keep `SessionHex`, Redis keys, and behavior bit for bit.

**Non-Goals:**
- Several decisions per cache key, or a typed delete under `ban` / `captcha` (existing debt `knowledge/debt/2026-09-19-multiple-decisions-per-cache-key.md`).
- Any allow set, `whitelist` / `allow` branch, or per-type map.
- A per-router fallback, or any change to `RemediationValue`, `bouncerOriginBasedDecisionRemap`, `bouncerLapiFailureAction`.
- A real-stack Pester test for the knob (requirement asks for unit and config tests).

## Decisions

- **Config surface.** `Config.LapiRemediationFallback string` (`json:"lapiRemediationFallback,omitempty"`), sorted between `LapiRedisReadHosts` and `LapiScheme`. Constants `LapiRemediationFallbackBan`, `LapiRemediationFallbackCaptcha`, `LapiRemediationFallbackIgnore` (named for this knob, not the `FailureAction*` constants, so the distinction from `bouncerLapiFailureAction` holds in code). `configuration.New` writes `ban`. `EffectiveLapiRemediationFallback(value string) string` maps empty to `ban`. Validation lives in `validateParamsRequired` next to the `LapiMode` enum check and runs on every middleware: error `LapiRemediationFallback: must be one of 'ban', 'captcha' or 'ignore'`; empty passes. Alternative: reuse `validateFailureAction` — rejected, it accepts `passthrough` and gates `captcha` on a captcha instance, neither of which applies to a connection knob.
- **Client field.** `lapi.New` stores the effective value on `Client` (`remediationFallback`). Subscribers never reach `lapi.New` for this connection, so their value is unused without extra code (same as `LapiStreamScopes`). Alternative: read per Bouncer — rejected, the knob changes what the shared DecisionStore holds.
- **Ingest kind.** `ingestRemediationKind` keeps its signature and returns `RemediationValue` for `ban` / `captcha`; for any other type it TRACE-logs `handleStreamCache:unknownType` with `type` and `fallback` attributes, then returns `BannedValue` (ban), `CaptchaValue` (captcha), or `""` (ignore). Empty means "not stored" at every site: `streamPutItem` returns false; the Range New branch skips the CIDR (no `rangeUpserts` entry, no `newCount`); `strongestLiveDecision` already skips any kind that is neither ban nor captcha, so it needs no change and an all-unknown list returns `NoBannedValue` via `queryLiveDecisions`. Alternative: a separate `(kind, stored bool)` return — rejected, empty already means "no remediation code" for `RemediationValue` callers and keeps the call sites unchanged.
- **Deleted rule.** One Client predicate `deletedTypeClearsStore(decisionType string) bool`: true for `ban` / `captcha`, true for any type when the fallback is `ban` or `captcha`, false for an unknown type under `ignore`. `streamDeleteItem` returns false when it is false; the Range Deleted branch skips the CIDR (no `rangeRemovals` entry, no `deletedCount`). Both shapes follow one rule (Symmetry). Alternative: inline the check twice — rejected, two copies of one policy drift. Alternative: derive it from `ingestRemediationKind(...) == ""` — rejected, that would TRACE-log on the delete path and tie delete semantics to the kind letter.
- **Counts.** Skipped rows do not count in `newCount` / `deletedCount`; those count rows written. The stream loops are not restructured (smallest durable delta).
- **Store identity.** `streamSession` gains `RemediationFallback string \`json:"remediationFallback,omitempty"\`` and `ownership` gains the same field. Both are filled from one helper on the lapi side that returns the effective value when it is not `ban` and `""` otherwise, so `omitempty` keeps the default payload identical to today's (no `SessionHex` or Redis key change on upgrade). A non-default value forks the store and refills with `startup=true`, like `lapiDefaultDecisionSeconds`. Alternative: Client-only (ownership) — rejected, two Clients with different values sharing one `SessionHex` would overwrite each other's slots, and switching `ban` → `ignore` would keep stale bans until TTL.
- **Origin remap.** No code change. The remap is one hop on the stored letter, so an unknown type stored as captcha follows `captcha` edges; under `ignore` nothing is stored to remap.
- **Tests.** `pkg/lapi/zzz_unknown_decision_type_test.go` switches its sample unknown type from `allow` to `throttle` (`challenge` may stay) and adds one table per knob value over stream Ip, header scope, Range New, Ip and Range Deleted, live pick, and the TRACE attribute. `pkg/lapi` session / ownership tests cover the default-hash and fork scenarios. `pkg/configuration/zzz_configuration_test.go` covers default, empty, each valid value, an invalid value, and `captcha` without a captcha instance.
- **Docs.** README: `LapiRemediationFallback` Variables entry (values, default, set it on the middleware that connects to LAPI, not `bouncerLapiFailureAction`, captcha on a router without captcha serves the ban page) and one paragraph under "## Decisions" with the whitelist / allow position and the upstream references. Wording: allowing traffic is done upstream by parser whitelists and LAPI allowlists (`cscli allowlists`), which stop or expire decisions at the source — not "never reach a bouncer" (LAPI allowlists also expire existing decisions, which the bouncer sees as ordinary deletes; `knowledge/research/ext_crowdsec_allowlists/`). Devdocs: Language term **Remediation fallback** in `core_plugin_lapi_stream-apply.md` (`_Avoid_`: passthrough, whitelist, allow, failure action), usage lines there and in `core_plugin_lapi_origin-based-decision-remap.md`, and the knob in the `core_plugin_lapi_reclaim-key.md` Ownership key / SessionHex terms. Remove the allow-over-ban pointer in `build_e2e_real.md`.

## Risks / Trade-offs

- [Under `ban` / `captcha` an unknown-type Deleted row still clears a ban held by another decision] → documented as the existing multi-decision debt; operators who need protection choose `ignore`.
- [Under `ignore` a `whitelist` row next to a ban does not lift the ban] → intended; README says allowing belongs to parser whitelists / LAPI allowlists.
- [`captcha` fallback on a router without a captcha subscription serves the ban page] → same path as an ordinary LAPI `captcha` decision; README states it.
- [Changing the knob on a running Redis deployment forks the store] → new `SessionHex` prefix refills from LAPI with `startup=true`; old keys expire by TTL, same as `lapiDefaultDecisionSeconds`.
- [TRACE on every unknown type] → TRACE only, no new Info/Debug line.

## Migration Plan

- Default `ban` keeps #198 behavior, `SessionHex`, and Redis keys; no operator action on upgrade.
- Operators who want the CrowdSec `remediation_fallback: ignore` behavior set `lapiRemediationFallback: ignore` on the middleware that connects to LAPI.
- Rollback: remove the knob; unknown types return to always-ban, and a store forked by a non-default value is abandoned and refilled under the default `SessionHex`.
