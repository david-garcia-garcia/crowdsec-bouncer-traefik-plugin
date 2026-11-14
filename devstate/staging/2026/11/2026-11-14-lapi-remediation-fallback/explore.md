# Explore

## Concepts

Units this change touches (all paths in the worktree):

- `pkg/configuration/configuration.go` `Config` (Lapi* block l.121-152), `New` (l.201), `validateParamsRequired` (l.772; enum checks such as `validateFailureAction` l.170 and `LapiMode` l.826 live here). Job: public Traefik config, defaults, validation. The new field `LapiRemediationFallback` sorts between `LapiRedisReadHosts` and `LapiScheme`.
- `pkg/lapi/client.go` `Client` (l.41) and `New` (l.108). Job: one reclaimed LAPI connection. Opener-only knobs are read here from the connecting middleware's config (example: `LapiStreamScopes` l.137-139).
- `pkg/lapi/client_decisions.go`. Job: LAPI ingest mapping. `ingestRemediationKind` (l.41) maps type to store letter (unknown is ban + TRACE `handleStreamCache:unknownType`); `streamPutItem` (l.54) builds the Ip/header New row; `streamDeleteItem` (l.85) builds the Ip/header Deleted row and never reads `item.Type`; `strongestLiveDecision` (l.161) picks the live winner by ingest kind; `queryLiveDecisions` (l.94) returns `NoBannedValue` when nothing is picked (l.117-119).
- `pkg/lapi/client_stream.go` `fetchAndApplyStreamDecisions` (l.108). Job: stream apply. The Range branch is inline: Deleted loop l.131-137 appends every CIDR to `rangeRemovals` regardless of type; New loop l.158-166 upserts with `ingestRemediationKind`.
- `pkg/lapi/identity.go` `ownershipFrom` (l.75) and `pkg/lapi/session.go` `sessionFrom` (l.48). Job: Client reclaim key and DecisionStore identity (`SessionHex`, also the Redis key prefix).
- `pkg/bouncer/bouncer.go` `handleCaptchaKindServeHTTP` (l.405-415) and `pkg/bouncer/origin_based_decision_remap.go` `applyOriginBasedDecisionRemap` (l.56). Read-only for this change: what a stored captcha does on a router, and how the per-router remap reads the stored letter.
- Docs: `README.md` (Decisions l.99, Remediation l.125, "Choose what happens when CrowdSec is down" l.494, Variables Lapi* l.719-791), `knowledge/devdocs/core_plugin_lapi_stream-apply.md` l.22, `knowledge/devdocs/core_plugin_lapi_origin-based-decision-remap.md` l.15/20/22, `knowledge/devdocs/build_e2e_real.md` l.66, `knowledge/debt/2026-09-19-multiple-decisions-per-cache-key.md`.

How they connect:

```
Traefik Config (connecting middleware, lapiEnabled: true)
   │ lapiRemediationFallback = ban | captcha | ignore (default ban)
   ▼
lapi.Open ──► OwnershipKey (identity.go)      SessionHex (session.go) ──► DecisionStore / Redis prefix
   │
   ▼
lapi.Client (holds the effective fallback)
   │
   ├─ stream New    Ip/header ─ streamPutItem ─┐
   │                Range ──── inline loop ────┼─► ingestRemediationKind(type)
   ├─ stream Deleted Ip/header ─ streamDeleteItem (type ignored today)
   │                Range ──── inline loop (type ignored today)
   └─ live/none ─ queryLiveDecisions ─ strongestLiveDecision ─► ingestRemediationKind
                                                                   │
                     ban/captcha ─► RemediationValue (unchanged)    │ unknown type ─► fallback:
                                                                   │   ban → t, captcha → c, ignore → not stored / not picked
   DecisionStore letter ──► Bouncer (per router): applyOriginBasedDecisionRemap (one hop on stored letter)
                                               └─ captcha letter on a router without captcha → WARN + ban page
```

Call sites that matter (roots searched: `pkg/`, repo-root `*.go`; `vendor/` and `devstate/` excluded):

- `ingestRemediationKind`: 4 production call sites (`client_decisions.go` l.56, l.126, l.164; `client_stream.go` l.161). Tests: `zzz_unknown_decision_type_test.go`, `zzz_origin_based_decision_remap_store_test.go`.
- `streamPutItem`: 2 (`client_decisions.go` l.32 `storeStreamDecision`, `client_stream.go` l.169). `streamDeleteItem`: 2 (`client_decisions.go` l.77 `deleteStreamDecision`, `client_stream.go` l.139). `storeStreamDecision` / `deleteStreamDecision` are only called from tests (`zzz_ipcachekey_test.go`, `zzz_origin_intern_test.go`).
- `strongestLiveDecision`: 1 (`client_decisions.go` l.116). `queryLiveDecisions`: 2 (`client_live.go` l.31 IP query, `client_decisions.go` l.183 header-scope query).
- `RemediationValue`: `pkg/decisionscope/lookup.go` l.25, used at ingest and by `pkg/bouncer/origin_based_decision_remap.go` l.52. Not changed.
- Existing `allow` sample in tests: `zzz_unknown_decision_type_test.go` l.18, l.37-42, l.73-87. In live specs: `core_plugin_lapi_origin-based-decision-remap/spec.md` scenarios l.48-50 and l.87-89.

Reproduce (measured on this worktree, HEAD 25321878):

- `go test ./pkg/lapi/ -run 'Unknown|LiveLookupEmptyList' -count=1 -v`: 6 tests PASS. Confirms today's behavior: `challenge` / `allow` store as ban on stream Ip, Range `allow` stores ban, live `challenge` remediates as ban and outranks captcha.
- Throwaway test in a temp copy of HEAD (`git archive`, deleted after): tick 1 stores Ip ban `203.0.113.7` and Range ban `10.0.0.0/8` (lookup `t`/`t`); tick 2 sends only Deleted rows of type `throttle` for the same Ip and CIDR; lookup becomes `""`/`""`. **Reproduced:** an unknown-type Deleted row clears a ban held by another decision, for both Ip and Range.
- No `LapiRemediationFallback` / `remediationFallback` anywhere in the tree outside `devstate/` and research notes (grep). There is no knob today.
- Identity rule (`skill:opd-explore` "who already owns that fact"): not applicable. This change sets no client address, user, tenant, Host, or trust hop.

Outside facts used:

- In-tree research: `knowledge/research/ext_crowdsec_decisions_scopes/` (swagger: type "might be 'ban', 'captcha' or something custom"; `cscli decisions add --type` examples `ban`, `captcha`, `throttle`; LAPI `FormatDecisions` copies Type onto the wire), `knowledge/research/ext_crowdsec_bouncers_failure-action/` (bouncer spec `remediation_fallback` "defaults ignore/ban/captcha"; nginx `FALLBACK_REMEDIATION`; cs-firewall-bouncer default `supported_decisions_types: [ban]`; `FALLBACK_REMEDIATION` is not backend unavailability).
- New research written by this phase (background subagent, `skill:opd-research:Delegate`), listed in `knowledge.md`:
  - `knowledge/research/ext_crowdsec_bouncers_remediation-fallback/`: the bouncer spec says "Defaults to ignore/ban/captcha configurable field remediation_fallback" and "If ignored, you don't even need to store the decision", and says nothing about delete. cs-firewall-bouncer (`cmd/root.go` L68-69, L108-109 @a09363ee) applies `supported_decisions_types` (default `[ban]`) to both add and delete ("decisions for ip '%s' will not be deleted because its type is '%s'") and has no fallback. lua-cs-bouncer (@4aad1dfa) maps any type other than `ban` / `captcha` / `challenge` to `FALLBACK_REMEDIATION` (`ban` | `captcha`; `ban` in the shipped config) at request time, and deletes by key without checking the type. This supports `ignore` = skip on add and on delete, and `ban` / `captcha` = keep today's untyped delete.
  - `knowledge/research/ext_crowdsec_allowlists/`: parser / postoverflow whitelists stop new decisions ("any existing decisions will still be applied"). LAPI allowlists (`cscli allowlists`) block new decisions. In source (crowdsec @e20782bb `pkg/database/allowlists.go` `ApplyAllowlistsToExistingDecisions`) they also expire existing matching decisions of any type; inferred, those reach a bouncer as ordinary stream `deleted` rows. No owner defines a `whitelist` or `allow` decision type (`authority: inference`: swagger "'ban', 'captcha' or something custom"; the only engine type constant is `DecisionTypeBan`; `allow` exists only as an AppSec per-request verdict).
  - Wording correction for README / devdocs / card: requirement.md says allowlists "act before a decision exists and never reach a bouncer". That holds for parser whitelists only. LAPI allowlists also expire existing decisions, which the bouncer then sees as normal deletes. Write "allowing traffic is done upstream by parser whitelists and LAPI allowlists, which stop or expire decisions at the source", not "never reach a bouncer".
- Devdocs consumed: `core_plugin_lapi_stream-apply.md`, `core_plugin_lapi_origin-based-decision-remap.md`, `core_plugin_lapi_reclaim-key.md`, `core_plugin_lapi_scope-union.md`, `core_plugin_middleware_instance-slots.md`, `build_e2e_real.md`. No devdocs written in explore (see the Language row below).

## Decisions

- Background (keep on the card): fork PR #198 (https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/198) made every LAPI type other than `ban` / `captcha` ingest as ban, following upstream issue #402 point 1 (https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/402) and upstream PR #403 point 1 (https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403). Upstream PR #433 (https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/433) proposes treating `whitelist` decisions as an allow; this change rejects that model.
- Position (keep on the card, README and devdocs): `whitelist` and `allow` are not valid CrowdSec decision types, and using decisions to allow traffic is an inadequate way to manage whitelists. The LAPI stream says WHAT TO BLOCK, not WHAT TO ALLOW. Allowing traffic belongs to parser whitelists and LAPI allowlists (`cscli allowlists`), which stop or expire decisions at the source (see the wording correction under Concepts). Source: requirement.md "What CrowdSec documents"; `ext_crowdsec_allowlists`; human, chat 2026-11-14.
- Seam: one knob `lapiRemediationFallback` (`ban` | `captcha` | `ignore`, default `ban`) on the LAPI connection config, read by `lapi.New` from the connecting middleware and held on `lapi.Client`. Human, chat 2026-11-14.
- Seam: the mapping stays at LAPI ingest in `pkg/lapi`: `ingestRemediationKind` returns the fallback letter for unknown types (`t`, `c`) or "not stored" under `ignore`; `streamPutItem`, the Range New branch and `strongestLiveDecision` skip a "not stored" type; `streamDeleteItem` and the Range Deleted branch skip an unknown type only under `ignore`.
- Seam: the knob enters `ownershipFrom` and `sessionFrom` (see the store-identity row), so a value change Opens a new Client and a new DecisionStore that refills with `startup=true`.
- Under `ban` / `captcha`, Deleted keeps today's whole-slot / whole-CIDR delete for any type. That is the existing multi-decisions-per-key debt, not this change. Human, chat 2026-11-14.
- `RemediationValue`, `bouncerOriginBasedDecisionRemap`, `bouncerLapiFailureAction`, and the TRACE stem `handleStreamCache:unknownType` keep their semantics.
- Rejected: value name `passthrough` (reads as "let this IP through", allow semantics; it is also a `bouncerLapiFailureAction` value). Human, chat 2026-11-14.
- Rejected: a per-type map (`{throttle: captcha, ...}`) and any `whitelist` / `allow` branch in code. One value, no type name special-cased. Human, chat 2026-11-14; requirement Desired 3.
- Rejected: per-router (Bouncer) fallback. The knob changes what is stored in the shared DecisionStore, so it belongs to the connection (requirement Out of scope; reclaim-key devdoc).
- Rejected: upstream #433's in-memory allow set and Range-in-stream option (requirement Out of scope).
- Rejected: restoring the "Allow is a whitelist" Pester test or an allow-as-veto lookup rule (requirement Desired 6).
- Live contract: `core_plugin_lapi_origin-based-decision-remap` (unknown type is ban, l.16, scenarios l.44-54, l.87-89), `core_plugin_decisions_scopes` (l.122, scenario l.126), `core_plugin_lapi_reclaim-key` (SessionHex and ownership field lists, l.8), `core_plugin_middleware_config-validation` (enum validation), and possibly `core_plugin_lapi_stream-apply` (Deleted under `ignore`). Propose picks the host for the new requirement and writes the deltas.

## Open questions

- Q: Where do README, devdocs and the delivery card state the position on `whitelist` / `allow` decisions, and with which references?
  Rank: additive asked — new documentation text; requirement Desired 5 and "Delivery card (must)"
  Decision: assumed — README: one paragraph under "## Decisions" (after the scope list) plus the `LapiRemediationFallback` Variables entry, which also says it is not `bouncerLapiFailureAction`. Devdocs: the stream-apply and origin-remap packets. Card: codereview's Delivery axis writes it into `codereview_delivery.md` `## Motivation`. Text in all three: `whitelist` and `allow` are not valid CrowdSec decision types and are an inadequate way to manage whitelists, because the LAPI stream is designed to say WHAT TO BLOCK, not WHAT TO ALLOW; use parser whitelists or LAPI allowlists (`cscli allowlists`). References: upstream issue #402 point 1 (https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/402), upstream PR #403 point 1 (https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403), upstream PR #433 whitelist part (https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/433), fork PR #198 (https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/198). Source: requirement.md; human, chat 2026-11-14.
  By: explore

- Q: Must `lapiRemediationFallback: captcha` be rejected when the router has no captcha instance, and what does a stored captcha do on such a router?
  Rank: additive asked — validation of a knob this change creates; requirement Desired 1 ("Any other value is rejected by config validation")
  Decision: resolved — no extra rejection; validation accepts exactly `ban`, `captcha`, `ignore` (plus empty as `ban`, see the default row). An unknown type stored as captcha takes the same path as an ordinary LAPI `captcha` decision: a router that did not subscribe to captcha WARNs `crowdsec bouncer captcha unsubscribed` and serves the ban page (`pkg/bouncer/bouncer.go` `handleCaptchaKindServeHTTP` l.405-415; `core_plugin_lapi_origin-based-decision-remap.md` "missing provider still falls back to ban rendering"). Ordinary captcha decisions are not rejected at config time, and the knob lives on the LAPI connection, which has no router to check (`validateFailureAction` gates only per-router failure actions). README states the downgrade. Source: verified in code; human, chat 2026-11-14.
  By: explore

- Q: With a shared LAPI connection (`lapiInstanceName`), which middleware owns the knob, and is a subscriber's value rejected?
  Rank: additive asked — new field on the LAPI config; requirement Desired 1 ("on the LAPI configuration")
  Decision: resolved — opener-only, like `lapiStreamScopes`: `lapi.New` reads it from the middleware with `lapiEnabled: true`; a subscriber's value is unused and not rejected, the same as every other `lapi*` knob (no subscriber rejection exists; `validateOpenVsSubscribe` l.419 only rejects a leftover instance name or secret when nothing owns or bounces). README says "Set it on the middleware that connects to LAPI", as for `LapiStreamScopes` (README l.517, l.773). Source: verified in code; human, chat 2026-11-14.
  By: explore

- Q: Must the knob enter `SessionHex` and the ownership key?
  Rank: additive incidental — adds one field to the `sessionFrom` / `ownershipFrom` payloads; existing callers keep working and a default config keeps its hash; no requirement line names store identity
  Decision: assumed — yes, both. Ownership key: the Client holds the value, so a change must Open a new Client (same rule as every other `lapi*` knob in `ownershipFrom`). `SessionHex`: the knob changes what is stored. Two middleware names with the same `SessionHex` share one DecisionStore, and Redis instances share keys by the `SessionHex` prefix, so without it two values would overwrite each other (last poll wins), and a switch from `ban` to `ignore` would keep the old bans until TTL. With it, a change forks the store and refills with `startup=true` (same as `lapiDefaultDecisionSeconds` and `lapiStreamScopes`, `core_plugin_lapi_reclaim-key.md`). Encode the field only when the effective value is not `ban` (`omitempty`), so existing deployments keep their `SessionHex` and Redis keys on upgrade. This also settles the requirement Unknown on Redis multi-instance runs. Propose adds the `core_plugin_lapi_reclaim-key` delta.
  By: explore

- Q: Is empty config `ban` at runtime, or is the default written in `New`?
  Rank: additive asked — default of a knob this change creates; requirement Desired 1 ("Default `ban`")
  Decision: assumed — mirror `BouncerLapiFailureAction`: `configuration.New` writes `ban`; validation accepts empty; one effective-value helper maps empty to `ban` and is used by `lapi.New` and by the session / ownership payloads. Constants are named for this knob (not the `FailureAction*` constants), so the README distinction from `bouncerLapiFailureAction` holds in code too.
  By: explore

- Q: How does ingest signal "not stored" under `ignore`, and how does the Deleted path learn the type rule?
  Rank: bounded asked — changes `ingestRemediationKind` and the stream / live call sites; 4 production call sites of `ingestRemediationKind`, 2 of `streamPutItem`, 2 of `streamDeleteItem`, 1 of `strongestLiveDecision` enumerated above (roots `pkg/`, repo-root `*.go`) and all migrated here; requirement Desired 2 names stream New, stream Deleted and live/none
  Decision: assumed — `ingestRemediationKind` returns an empty kind for an unknown type under `ignore` (still TRACE-logged). Every ingest site treats empty as not stored: `streamPutItem` returns false; the Range New branch skips; `strongestLiveDecision` already skips anything that is neither ban nor captcha, so an IP whose only rows are unknown-type returns `NoBannedValue` (`queryLiveDecisions` l.117-119) and live mode caches that pass like any empty result. Deleted: one Client predicate named for the job (whether this Deleted type may clear stored state) is used by `streamDeleteItem` and the Range Deleted branch, so both shapes follow one rule (`skill:opd-commandments:Symmetry and consistency`). Skipped rows do not count in `newCount` / `deletedCount` (they count rows written). Do not restructure the loops (`Smallest durable delta`). Propose named the predicate `deletedTypeClearsStore` on `Client` (true for `ban` / `captcha`, true for any type under `ban` / `captcha` fallback, false for an unknown type under `ignore`); see `openspec/changes/lapi-remediation-fallback/design.md`.
  By: propose

- Q: Under `ignore`, what does a stream Deleted row of an unknown type do; under `ban` / `captcha`?
  Rank: additive asked — new branch in the delete path for a value this change creates; requirement Desired 2 (`ignore` bullet) and Out of scope (typed delete)
  Decision: resolved — `ignore`: deletes nothing (neither Ip/header slot nor Range CIDR), mirroring cs-firewall-bouncer, which does not delete decisions whose type it does not support. `ban` / `captcha`: unchanged whole-slot / whole-CIDR delete (reproduced above); that is the existing debt in `knowledge/debt/2026-09-19-multiple-decisions-per-cache-key.md`. Source: human, chat 2026-11-14.
  By: explore

- Q: Should `ignore` log the skipped type, and at what level?
  Rank: additive incidental — log attribute on a branch this change creates; no criterion names logging; requirement Out of scope keeps the stem and level
  Decision: assumed — keep the TRACE stem `handleStreamCache:unknownType` for every unknown type and add the effective fallback as an attribute; no new Info/Debug line.
  By: explore

- Q: How does the fallback interact with `bouncerOriginBasedDecisionRemap`?
  Rank: additive incidental — documentation of unchanged behavior; requirement Out of scope ("Changing ... `bouncerOriginBasedDecisionRemap` semantics")
  Decision: assumed — no code change. The remap is one hop on the stored letter (`applyOriginBasedDecisionRemap` l.56, `originBasedDecisionRemapFromKind` l.75), so an unknown type stored as captcha follows `captcha` edges and one stored as ban follows `ban` edges, as unknown-as-ban already does today. Under `ignore` there is nothing to remap. Devdocs and README say so in one line.
  By: explore

- Q: Which sample type do tests and spec scenarios use for "unknown type"?
  Rank: bounded asked — edits existing tests and scenarios, enumerated: `zzz_unknown_decision_type_test.go` l.18, l.37-42, l.73-87; `core_plugin_lapi_origin-based-decision-remap/spec.md` scenarios l.48-50, l.87-89; requirement Desired 3 and 7, Tension 2
  Decision: resolved — replace `allow` with `throttle` (documented in `cscli decisions add --type`, `ext_crowdsec_decisions_scopes`). `challenge` may stay: it carries no allow meaning. New tests cover each knob value on stream Ip, header scope, Range, Deleted and live, plus config validation. Source: human, chat 2026-11-14.
  By: explore

- Q: What happens to the debt note and the `build_e2e_real.md` pointer?
  Rank: bounded asked — edits two existing docs, both enumerated; requirement Desired 6
  Decision: resolved — in `knowledge/debt/2026-09-19-multiple-decisions-per-cache-key.md` remove the allow-as-veto framing ("Why this follow-up" allow example, "Risks", "Observed on the parked test" allow lines, "Required shape" allow-means-pass, apply-order steps 4-6 allow parts, "Restore the real-stack test", the restore-requirement line, and "Recovered Pester file"); replace the stale "stream skips `type=allow`" line with today's rule (unknown types follow `lapiRemediationFallback`); keep the real debt (two bans, ban + captcha, a typed delete clearing the whole slot). Remove the `build_e2e_real.md` l.66 bullet that points at the allow-over-ban Pester file. Source: human, chat 2026-11-14.
  By: explore

- Q: Do live specs change in this run?
  Rank: additive asked — spec deltas follow the knob; requirement Affected lists the live specs
  Decision: assumed — yes, through propose deltas: `core_plugin_lapi_origin-based-decision-remap` and `core_plugin_decisions_scopes` change "unknown is ban" to "unknown follows `lapiRemediationFallback` (default ban)"; `core_plugin_lapi_reclaim-key` adds the knob to the ownership and `SessionHex` lists; the knob itself (values, default, enum validation, opener-only, stream New / Deleted / live per value, TRACE attribute) lives in a new leaf `core_plugin_lapi_remediation-fallback` (FindSpecHost `new`); `core_plugin_middleware_config-validation` and `core_plugin_lapi_stream-apply` get no delta (the new leaf owns its validation and its Deleted rule, as `core_plugin_lapi_failure-action` owns its own). Journal: `specs.md`.
  By: propose

- Q: Which devdocs term names the knob, and when is it written?
  Rank: additive incidental — new Language entry; no criterion names devdocs Language (Desired 5 names usage docs)
  Decision: assumed — no devdocs write in explore (no code path exists yet, `skill:opd-devdocs:Consume then produce`). Implement or devdocsimpact adds **Remediation fallback** (the store letter for a LAPI type that is neither `ban` nor `captcha`; `_Avoid_`: passthrough, whitelist, allow, failure action) to `core_plugin_lapi_stream-apply.md`, and updates usage lines l.22 there and l.15/20/22 in `core_plugin_lapi_origin-based-decision-remap.md`, with the whitelist/allow position above.
  By: explore
