# Requirement
IssueKey: 2026-09-18-live-header-ban-cached-on-ip

## Problem
In live mode, `LiveLookup` writes the merged verdict (IP plus header scopes) onto the client-address cache slot. A header-scope ban therefore becomes an IP ban for `defaultDecisionSeconds`. Any later request from the same address with a different header identity inherits that ban. Header results are already stored on `HeaderScopeKey`; the IP slot must keep only the IP query result.

## Current (code)
- After scope merge, any active `chosen` is written to `cacheClient.Set(remoteIP, chosen, …)`. `pkg/lapi/client_live.go:43-46`
- `chosen` is the PreferRemediation merge of the IP query and every header-scope query, so a clean IP plus a banned username/country still takes this write. `pkg/lapi/client_live.go:27-42` `pkg/lapi/client_decisions.go:143-147`
- `mergeLiveScope` already stores each header result on `HeaderScopeKey(scope, identifier)` via `cacheLiveScope`. `pkg/lapi/client_decisions.go:142,150-160`
- A later live/stream/alone request reads `LookupCachedRemediation`, which treats an active value on `remoteIP` as a hit before header keys. `pkg/decisionscope/lookup.go:75-90` `pkg/bouncer/bouncer.go:191-214`
- Existing live tests assert the first-request return, not the IP slot after a header-only ban. `pkg/lapi/zzz_failure_action_test.go:144-156`
- `TestHunt_LiveLookupDoesNotCacheHeaderBanOnIP` is not in this tree (`not found` on `origin/master`). The hunter worktree proves the write at `client_live.go:43-46` fails that assertion.

## Desired
- Write only the IP query result to the IP cache key. Keep header remediations on `HeaderScopeKey`.
- A later cache lookup for the same IP and a different header value must not inherit another identity's ban.
- Include a regression test for that pair of facts.
- Bound the change to this defect only.

## Affected
- `pkg/lapi/client_live.go` (`handleNoStreamCache` IP-slot write)
- `pkg/lapi/zzz_*_test.go` (regression)
- `openspec/specs/core_plugin_decisions_scopes/spec.md` (propose decides fold vs new leaf)
- `knowledge/devdocs/core_plugin_lapi_connection.md` if usage must name the IP-slot vs header-slot rule (devdocsimpact)

## Out of scope
- Stream/alone apply order, CAPI login, captcha, AppSec, reclaim, `pkg/cache` key format
- Changing `HeaderScopeKey`, `LookupCachedRemediation` merge order, or live TTL math
- `none` mode (TTL 0 already skips live cache writes)
- Other hunt defects; do not land `TestHunt_*` as the product name unless implement reuses the assertion

## Unknowns
- Whether a clean IP query should write `NoBannedValue` on the IP key when a header scope is remediating (ticket says write the IP query result; that result is the clean IP value).
- Whether an IP ban plus a header ban must keep today's IP-key write of the IP ban (yes — that is the IP query result).

## Tensions
- Cited lines match dest `fad36a1` for `client_live.go:43-46` and `client_decisions.go:142,150-160`.
- The named hunt test is throwaway proof, not a dest test. The defect is the write in `handleNoStreamCache`, not a missing file on master.
- `core_plugin_decisions_scopes` already says Ip keys are exact-address and header scopes match headers; dest still writes a header ban onto the IP key. Propose records the fold.
