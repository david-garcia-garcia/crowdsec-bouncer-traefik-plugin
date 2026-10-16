# Explore

## Concepts

Units this change would touch:

- decisionscope.RemediationValue (pkg/decisionscope/lookup.go): maps LAPI type an/captcha to store letters 	/c; anything else is empty. Remap and tests rely on empty. Do not change.
- lapi.streamPutItem (pkg/lapi/client_decisions.go): Ip/header stream New ingest. Empty kind logs handleStreamCache:unknownType at Debug and skips (ok=false).
- handleStreamCache Range New (pkg/lapi/client_stream.go): Range ingest uses RemediationValue directly and skips empty kind (not streamPutItem).
- strongestLiveDecision / queryLiveDecisions / LiveLookup (pkg/lapi/client_decisions.go, pkg/lapi/client_live.go): live and none query. Unknown types never win; empty kind returns NoBannedValue. None does not cache; live caches only IsActiveRemediation.
- pplyOriginBasedDecisionRemap (pkg/bouncer/origin_based_decision_remap.go): RemediationValue(to) for weaken edges; empty means not a remediation code.
- logger.Trace (pkg/logger/logger.go): TRACE helper; slog has no Trace method.

`
LAPI type
    |
    +-- RemediationValue: ban->t, captcha->c, else empty
    |         |
    |         +-- remap to-token (must stay empty for unknown)
    |         |
    |         +-- ingest today: empty -> skip / allow
    |
    +-- desired ingest: ban/captcha as today; else ban + TRACE
`

Call sites of RemediationValue(: 5 production + tests. Roots searched: pkg/**/*.go. Production: pkg/lapi/client_decisions.go (3: streamPutItem, queryLiveDecisions, strongestLiveDecision), pkg/lapi/client_stream.go (1: Range upsert), pkg/bouncer/origin_based_decision_remap.go (1: remap to-token). Tests: pkg/decisionscope/zzz_lookup_test.go.

Reproduce: throwaway go test ./pkg/lapi -run TestExploreUnknownTypeIsSkippedOnMaster on this worktree (master HEAD ingest). Result: FAIL.
- streamPutItem type challenge: ok=false kind empty
- strongestLiveDecision type challenge: nil
- llow then captcha: picked captcha (unknown did not outrank)

Outside facts: in-tree knowledge/research/ext_crowdsec_appsec_bot-detection (LAPI/blocklist challenge has no body; fail closed to ban); knowledge/research/ext_crowdsec_bouncers_failure-action nginx FALLBACK_REMEDIATION=ban for unknown remediation. No new research folder.

Usage packets that will be stale after apply: knowledge/devdocs/core_plugin_lapi_stream-apply.md, knowledge/devdocs/core_plugin_lapi_origin-based-decision-remap.md (unknown type skip store). Language terms stay.

## Decisions

- Fail closed at LAPI ingest only: a new pkg/lapi helper maps wire type to store kind (an/captcha via RemediationValue; empty -> BannedValue) and TRACE-logs unknown types with stem handleStreamCache:unknownType. Call it from streamPutItem, Range upsert, strongestLiveDecision, and queryLiveDecisions.
- Do not change RemediationValue. Remap keeps empty as not a code.
- Empty live/stream lists stay no-remediation (existing len==0 / no New items).
- Live cache follows existing IsActiveRemediation: an ingested unknown becomes ban, so live memos it; none still does not cache.
- Live contract: MODIFY specs that currently skip/ignore unknown types (core_plugin_lapi_origin-based-decision-remap, core_plugin_decisions_scopes); stream-apply may need a scenario that Range/Ip unknown stores ban. Propose runs FindSpecHost.
- Rejected: copy upstream PR 403 root ouncer.go patch (master has no that file).
- Rejected: special-case only challenge (ticket names llow and anything else).
- Rejected: change RemediationValue default empty return.

## Open questions

- Q: Should stream Range upserts map unknown types to ban, not only streamPutItem?
  Rank: bounded asked — 1 Range call site in pkg/lapi/client_stream.go plus 3 other ingest sites in pkg/lapi (roots: pkg/); Desired names stream store and apply
  Decision: assumed — include Range in the ingest helper; still not RemediationValue.
  By: explore
- Q: Log unknown types on live pick with the stream stem handleStreamCache:unknownType?
  Rank: additive asked — new helper this change creates; Desired keep the existing message stem
  Decision: assumed — the helper TRACE-logs once per unknown type at every ingest call, including live.
  By: explore
- Q: Store LAPI type allow as ban despite whitelist debt?
  Rank: bounded asked — Desired names allow; existing debt file is not this ticket
  Decision: assumed — store allow as ban; leave the existing debt file; do not take whitelist work.
  By: explore
