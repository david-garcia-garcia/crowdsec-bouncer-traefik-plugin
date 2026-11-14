# Requirement
IssueKey: 2026-11-14-lapi-remediation-fallback

Source: caller spec (issueHost local), copied in full below from `ticket/source.md`. Grounded sections follow the spec.

---

## Spec: Add lapiRemediationFallback for unknown LAPI decision types

### Context

Fork PR #198 (https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/198, commit 3388bbca, on master, not released) made every LAPI decision type other than `ban` / `captcha` ingest as `ban`. It followed upstream issue #402 point 1 (https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/402) and upstream PR #403 point 1 (https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403).

Upstream PR #433 (https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/433, open) proposes special-casing decisions of type `whitelist` as an allow (skip on stream New, skip on stream Deleted, ignore in live, and an in-memory set that exempts a whitelisted IP from Range bans). Its Range-in-stream part is already covered by this fork and is out of scope here.

### What CrowdSec documents (researched 2026-11-14)

- LAPI swagger (`pkg/models/localapi_swagger.yaml`): Decision `type` is a free string, "might be 'ban', 'captcha' or something custom". No enum.
- `cscli decisions add --type`: "Decision type (ie. ban,captcha,throttle)". Profiles: "for example `ban`, `captcha`".
- `whitelist` and `allow` are NOT CrowdSec decision types. No official component gives them allow semantics.
- The LAPI decision stream is designed to say WHAT TO BLOCK, not WHAT TO ALLOW. Allowing traffic in CrowdSec is done with parser whitelists (https://docs.crowdsec.net/u/getting_started/post_installation/whitelists) and LAPI allowlists (`cscli allowlists`, https://docs.crowdsec.net/docs/next/local_api/centralized_allowlists). They act before a decision exists and never reach a bouncer.
- Bouncer spec (https://docs.crowdsec.net/docs/next/contributing/specs/bouncer_appsec_specs): remediation is "ban", "captcha" or "potentially any custom string"; unknown types follow `remediation_fallback`: "Defaults to ignore/ban/captcha"; "If ignored, you don't even need to store the decision".
- Official bouncers: lua-cs-bouncer maps any type other than ban/captcha/challenge to `FALLBACK_REMEDIATION` (default ban). cs-firewall-bouncer only applies `supported_decisions_types` (default ["ban"]) and ignores others on both add and delete ("decisions for ip '%s' will not be deleted because its type is '%s'").

### Desired

1. New config knob `lapiRemediationFallback` (Go field `LapiRemediationFallback`, json `lapiRemediationFallback`) on the LAPI configuration. Values: `ban` | `captcha` | `ignore`. Default `ban` (keeps #198 behavior). Any other value is rejected by config validation.
2. It applies only to LAPI decision types that are neither `ban` nor `captcha`, at LAPI ingest:
   - `ban`: ingested as ban (today).
   - `captcha`: ingested as captcha.
   - `ignore`: the decision is not stored. Stream `new`: Ip, header-mapped scopes and Range are all skipped. Stream `deleted`: an unknown-type row does not delete anything (neither the Ip/header slot nor the Range CIDR), so it cannot clear a ban another decision holds on the same value. Live/none: excluded from the strongest-decision pick; an IP whose only decisions are unknown-type passes.
3. Do not special-case `whitelist`, `allow`, or any other type name in code. The knob is the only policy.
4. The knob is not the LAPI-unreachable behavior; that stays `bouncerLapiFailureAction`. README must say so.
5. Record the decision in usage docs (devdocs) and README: `whitelist` / `allow` are not valid CrowdSec decision types; using decisions to allow traffic is an inadequate way to manage whitelists, because the LAPI stream is designed to say what to block, not what to allow; the supported way is parser whitelists / LAPI allowlists (`cscli allowlists`).
6. Correct `knowledge/debt/2026-09-19-multiple-decisions-per-cache-key.md`: remove the allow-as-veto framing and the recovered "Allow is a whitelist" Pester test (do not restore it); keep the real debt (several decisions on one key: two bans, ban+captcha, a typed delete clearing the whole slot).
7. Tests: unit tests for each knob value on stream (Ip, header scope, Range, deleted) and live; config validation test.

### Out of scope

- Upstream #433 Range-in-stream option and its in-memory AllowSet.
- Storing several decisions per cache key (existing debt).
- Any change to `bouncerLapiFailureAction`.

### Delivery card (must)

The delivery card must reference upstream issue #402 (point 1), upstream PR #403 (point 1), upstream PR #433 (whitelist part) and fork PR #198, and must state clearly that WHITELIST or ALLOW are not valid CrowdSec decisions and are an inadequate way to manage whitelists, because the LAPI stream is designed to say WHAT TO BLOCK, not WHAT TO ALLOW.

---

## Problem

Since fork PR #198 (commit 3388bbca, on `master`, unreleased) every LAPI decision type that is neither `ban` nor `captcha` is stored and applied as `ban`, with no way for the operator to choose otherwise. The CrowdSec bouncer spec defines a `remediation_fallback` (ignore / ban / captcha) for exactly this case. Separately, upstream PR #433 and this fork's own debt note treat `whitelist` / `allow` decisions as an allow; CrowdSec does not define those types, and the LAPI decision stream says what to block, not what to allow. Allowing traffic belongs to parser whitelists and LAPI allowlists (`cscli allowlists`), which act before a decision exists.

## Current (code)

Spec item 1 (config knob):
- No `LapiRemediationFallback` field: `pkg/configuration/configuration.go` `Config` (Lapi* block, l.121-152). `not found` anywhere in the tree outside `devstate/`.
- Defaults are set in `pkg/configuration/configuration.go` `New` (l.201); validation entry is `ValidateParams` (l.365). The closest enum validator is `validateFailureAction` (l.170), which accepts empty as `ban` and gates `captcha` on a captcha instance name.

Spec item 2 (ingest of non-ban / non-captcha types):
- Kind mapping: `pkg/lapi/client_decisions.go` `ingestRemediationKind` (l.41) returns `RemediationValue` for `ban`/`captcha`, else `BannedValue`, TRACE `handleStreamCache:unknownType`. No knob read.
- Stream `new` Ip and header-mapped scopes: `pkg/lapi/client_decisions.go` `streamPutItem` (l.54) always stores (ban for unknown types); it only skips Range.
- Stream `new` Range: `pkg/lapi/client_stream.go` `fetchAndApplyStreamDecisions` (New loop, l.153-167) upserts every non-empty CIDR with `ingestRemediationKind`.
- Stream `deleted` Ip and header-mapped scopes: `pkg/lapi/client_decisions.go` `streamDeleteItem` (l.85) deletes the slot for any type; it does not read `item.Type`.
- Stream `deleted` Range: `pkg/lapi/client_stream.go` `fetchAndApplyStreamDecisions` (Deleted loop, l.131-137) appends every non-empty CIDR to `rangeRemovals` regardless of type.
- Live/none Ip: `pkg/lapi/client_decisions.go` `strongestLiveDecision` (l.161) ranks by `ingestRemediationKind`, so an unknown type is a ban and outranks captcha; `queryLiveDecisions` (l.94) returns that kind. An IP whose only rows are unknown-type is banned today.
- Live/none header scopes: `pkg/lapi/client_decisions.go` `mergeLiveScope` (l.179) goes through `queryLiveDecisions` (same pick).

Spec item 3 (no special-casing of type names):
- `not found`: no `whitelist` / `allow` branch in `pkg/` production code. `allow` appears only in tests: `pkg/lapi/zzz_unknown_decision_type_test.go` (l.18, l.37-42, l.73-87) asserts `allow` / `challenge` store and rank as ban.

Spec item 4 (failure action is separate):
- `BouncerLapiFailureAction`: `pkg/configuration/configuration.go` l.90 (field), l.220 (default `ban`), l.810 (validation); applied in `pkg/bouncer/bouncer.go` `applyLapiFailureAction` (l.310). README entry `README.md` l.701 and "Choose what happens when CrowdSec is down" l.494. README does not mention unknown decision types.

Spec item 5 (docs):
- README: `README.md` "## Decisions" (l.99) and "## Remediation" (l.125) list `ban` / `captcha` only; no text on unknown types, `whitelist`, `allow`, parser whitelists or `cscli allowlists`. Variables list has no `LapiRemediationFallback` (Lapi* entries l.719-791).
- Usage docs: `knowledge/devdocs/core_plugin_lapi_stream-apply.md` l.22 and `knowledge/devdocs/core_plugin_lapi_origin-based-decision-remap.md` l.15, l.20, l.22 state "any other type is ban" with no knob.
- Live specs stating unknown is ban: `openspec/specs/core_plugin_lapi_origin-based-decision-remap/spec.md` l.16 (scenarios l.48, l.52, l.87) and `openspec/specs/core_plugin_decisions_scopes/spec.md` l.126 ("Unknown LAPI type is ban").

Spec item 6 (debt note):
- `knowledge/debt/2026-09-19-multiple-decisions-per-cache-key.md`: allow-as-veto framing in "Why this follow-up" (ban + `type=allow` example), "Risks", "Observed on the parked test" ("Product still needs a lookup rule for allow-as-veto"), "Required shape" (allow means pass), "Suggested apply order" steps 4-6, "Restore the real-stack test" and the full "Recovered Pester file" (`Context "Allow is a whitelist"`). It also says stream skips `type=allow` on empty `RemediationValue`, which is stale since #198 (unknown types now store as ban).
- `knowledge/devdocs/build_e2e_real.md` l.66 points readers at that allow-over-ban Pester file.

Spec item 7 (tests):
- Existing #198 coverage: `pkg/lapi/zzz_unknown_decision_type_test.go` (stream put, live strongest, live lookup, Range upsert, TRACE log). No knob tests; no unknown-type `deleted` tests.
- Config tests live in `pkg/configuration/zzz_configuration_test.go`; no `LapiRemediationFallback` case.

## Affected

- `pkg/configuration/configuration.go` (field, default, validation) and `pkg/configuration/zzz_configuration_test.go`.
- `pkg/lapi/client_decisions.go`, `pkg/lapi/client_stream.go`, `pkg/lapi/client.go` (`New`, where config reaches the Client), `pkg/lapi/zzz_unknown_decision_type_test.go`.
- `README.md` (Variables entry, Decisions / Remediation text, failure-action distinction).
- `knowledge/devdocs/core_plugin_lapi_stream-apply.md`, `knowledge/devdocs/core_plugin_lapi_origin-based-decision-remap.md`, `knowledge/devdocs/build_e2e_real.md`.
- `knowledge/debt/2026-09-19-multiple-decisions-per-cache-key.md`.
- Live specs `openspec/specs/core_plugin_lapi_origin-based-decision-remap/spec.md`, `openspec/specs/core_plugin_decisions_scopes/spec.md`, and possibly `openspec/specs/core_plugin_lapi_stream-apply/spec.md` (propose decides).
- Delivery card (must, carried to every card Set): reference upstream issue #402 point 1 (https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/402), upstream PR #403 point 1 (https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403), upstream PR #433 whitelist part (https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/433) and fork PR #198 (https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/198); state that WHITELIST or ALLOW are not valid CrowdSec decisions and are an inadequate way to manage whitelists, because the LAPI stream is designed to say WHAT TO BLOCK, not WHAT TO ALLOW. `deliver_card` builds Motivation only from `codereview_delivery.md` `## Motivation`, so codereview's Delivery axis must write this there; explore should keep the references on its rows.

## Out of scope (inferred extras, not taken)

- A per-router (Bouncer) fallback instead of per-LAPI-connection: the spec places the knob on the LAPI configuration.
- Changing `RemediationValue` or `bouncerOriginBasedDecisionRemap` semantics for unknown types.
- A real-stack (Pester) e2e for the knob: spec item 7 asks for unit and config tests only.
- Changing the TRACE log stem `handleStreamCache:unknownType` or its level.
- Typed delete under the `ban` / `captcha` fallback values (an unknown-type `deleted` row keeps today's whole-slot delete; that is the existing multi-decision debt).

## Unknowns

- Whether `lapiRemediationFallback: captcha` must be rejected when the router has no captcha instance (as `validateFailureAction` does for failure actions), and what a stored captcha does on a router without captcha. The spec only says "any other value is rejected".
- Shared-connection setups: the LAPI Client is shared by routers via `lapiInstanceName`. Whether the knob is owner-only (like other Lapi* connection fields) and how a subscriber router that sets it is treated (`validateOpenVsSubscribe`, `pkg/configuration/configuration.go` l.419).
- Whether empty config maps to `ban` at runtime (like `EffectiveFailureAction`) or the default is written in `New`; both meet "default `ban`".
- Whether `ignore` should log the skipped type (today TRACE on ingest) and at what level.
- Redis / shared-cache multi-instance runs: two Clients with different fallback values writing the same DecisionStore keys. Blast radius not measured.
- Whether live specs change in this run through propose deltas (explore / propose own).

## Tensions

- Spec item 2 `ignore` on stream `deleted` (an unknown-type row deletes nothing) vs code today: `streamDeleteItem` and the Range `deleted` loop never read the type, so any `deleted` row clears the slot or CIDR. Under `ban` / `captcha` the spec is silent on delete; today's behavior (delete regardless of type) would stay.
- Spec item 3 (no type-name special-casing) vs `pkg/lapi/zzz_unknown_decision_type_test.go`, which uses `allow` as its sample unknown type. The tests may keep `allow` as a sample string, but must not read as allow semantics.
- Spec item 6 vs the debt note: the note says "Product still needs a lookup rule for allow-as-veto" and asks to restore the allow Pester test and a spec requirement "Real stack covers CrowdSec allow as a whitelist"; the spec says remove that framing and do not restore the test. `knowledge/devdocs/build_e2e_real.md` l.66 echoes the debt note.
- Upstream PR #433 treats `whitelist` as an allow; this spec rejects that model and offers `ignore` as the only policy for unknown types. Under `ignore`, a `whitelist` row next to a ban does not lift the ban (it is just not stored), which is intended.
- Live specs (`core_plugin_lapi_origin-based-decision-remap`, `core_plugin_decisions_scopes`) state unknown means ban unconditionally; with the knob they become "unknown follows the fallback (default ban)".
