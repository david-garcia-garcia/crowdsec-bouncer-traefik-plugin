## Context

See `proposal.md` Why. Baseline is `master` `fad36a1`. Facts measured on this worktree (`devstate/2026/09/2026-09-18-live-header-ban-cached-on-ip/explore.md`):

- `handleNoStreamCache` (`pkg/lapi/client_live.go:27-46`) queries `?ip=` first, then merges each mapped header through `mergeLiveScope`. After the loop, any active `chosen` (PreferRemediation of IP plus headers) is written to `cacheClient.Set(remoteIP, chosen, …)`.
- `mergeLiveScope` already stores each header result on `HeaderScopeKey(scope, identifier)` via `cacheLiveScope` (`pkg/lapi/client_decisions.go:142,150-160`).
- `LookupCachedRemediation` treats an active value on `remoteIP` as a hit before header keys (`pkg/decisionscope/lookup.go:75-90`). A later live request from the same address with a different header therefore inherits the first identity's ban.
- Throwaway hunt assertion: after a clean `?ip=` plus Country ban `FR`, `cacheClient.Get("1.2.3.4")` returned `"t\x1fCAPI"`. `TestLiveLookup_ScopeBanWins` only asserts the first-call return.
- Identity owners: `pkg/ip.GetRemoteIP` owns the client address; `pkg/bouncer` stores it on `clientRequest.remoteIP` and passes that string into `LiveLookup`. `decisionscope.RequestScopeValues` owns header identity. `handleNoStreamCache` consumes those outputs.

FindSpecHost:

```
verdicts:
  - { deltaId: live-ip-slot-holds-ip-query, fold|new: fold, spec-id: core_plugin_decisions_scopes, confidence: high, candidates: [core_plugin_decisions_scopes, core_plugin_lapi_failure-action, core_plugin_lapi_connection, core_plugin_lapi_query-round-trip] }
```

Search: family `core_plugin_decisions` holds `scopes` (already the owner of "Ip decisions stay exact-address keys" and header-scope matching — the live IP-slot write is a one-requirement adjustment to that leaf). `core_plugin_lapi_failure-action` owns fail-closed / no negative IP-key write on a header-query error; this change must not weaken that. `connection` is transport/reclaim. `query-round-trip` is the HTTP exchange. No new leaf for one cache-slot write.

## Goals / Non-Goals

**Goals:**

- The live IP cache key holds the `?ip=` query result, not the merged header-plus-IP verdict.
- Header remediations stay on `HeaderScopeKey` via the existing `cacheLiveScope` owner.
- A later cache hit for the same IP and a different header does not inherit the first identity's ban.
- Fail-closed (no none payload on the IP key when a header query failed and the merge is not active) stays true.

**Non-Goals:**

- Changing `HeaderScopeKey`, `LookupCachedRemediation` merge order, or the `liveCacheTTL` formula.
- Re-parsing `RemoteAddr` or re-reading headers in `pkg/lapi`.
- Stream/alone apply, CAPI login, captcha, AppSec, reclaim, `pkg/cache` key format.
- `none` mode (TTL 0 already skips live cache writes).
- Landing `TestHunt_*` as the product name.
- Rewriting `core_plugin_lapi_connection.md` usage in this phase (implement / `sbs-dev-devdocsimpact` after the write matches).

## Decisions

1. **Write the IP query result, not `chosen`.** Keep the `?ip=` remediation in a local (`ipResult` / its duration) before the header loop mutates `chosen`. After the loop, the IP-key write uses that local. Alternative: write `chosen` only when it equals `ipResult` — rejected, a header-only ban would skip the IP-key write and leave a miss that re-queries LAPI; Desired is to store the clean IP result.
2. **IP-key TTL follows the IP query.** Active IP result uses existing `liveCacheTTL(ipDuration, defaultDecisionSeconds)`. Clean IP result uses `defaultDecisionSeconds`, same as today's all-clean write and `cacheLiveScope` for a non-active header. Alternative: reuse the merged `parsedDuration` (header winner) for the IP slot — rejected, that applies header duration to an IP fact.
3. **Fail-closed write gate stays on the none payload.** Write an active IP result whenever live caching is on. Write a clean IP result only when there is no header-scope query error. A clean IP plus a remediating header and no error writes `NoBannedValue`. A clean IP plus a failed header and no active merge writes nothing. Alternative: always write `ipResult` including on scope error — rejected, `core_plugin_lapi_failure-action` forbids a negative IP-key entry so the unverified allow does not survive.
4. **`cacheLiveScope` remains the header-slot owner.** Do not add a second header write in `handleNoStreamCache`. Alternative: also write the merged `chosen` onto a new key — rejected, header keys already exist.
5. **Consume identity owners.** `LiveLookup` keeps taking `remoteIP` and `scopes` as today. Do not parse `RemoteAddr` or call `RequestScopeValues` from `pkg/lapi`. Alternative: reconstruct the client address from the request in the live client — rejected, `GetRemoteIP` already owns that fact.
6. **One dest-style test.** `TestLiveLookup_IPSlotKeepsIPQueryResult` beside `TestLiveLookup_ScopeBanWins` in `pkg/lapi/zzz_failure_action_test.go`. Assert the IP slot is the IP query result **and** `LookupCachedRemediation` for the same IP plus a different header does not inherit the header ban. Keep `TestLiveLookup_ScopeBanWins` (first-call return). Do not commit `TestHunt_LiveLookupDoesNotCacheHeaderBanOnIP`.

## Risks / Trade-offs

- [A later request with a new header hits a clean IP slot and skips LiveLookup for that header] → Existing `LookupCachedRemediation` treats a present IP key as a complete hit when header keys miss. Changing that merge is out of scope; Desired is that the new header does not inherit the old ban.
- [Writing `NoBannedValue` on the IP key during a header-only ban adds a negative IP entry that dest did not write (dest wrote the ban)] → Accepted; that is the fix. Fail-closed still skips the none write when a header query failed.
- [Captcha on a header uses the same write] → Accepted; `IsActiveRemediation` already covers captcha and splitting a captcha path would be a second job.

## Migration Plan

No public JSON/YAML key changes. Existing Redis/memory IP keys that already hold a header ban expire with their TTL. Rollback is revert.

## Open Questions

None.
