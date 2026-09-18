# Explore
IssueKey: 2026-09-18-live-header-ban-cached-on-ip

## Concepts

Live/none cache miss calls `LiveLookup` → `handleNoStreamCache`. That function queries LAPI `?ip=` first, then each mapped header via `mergeLiveScope`. `mergeLiveScope` already stores every header result on `HeaderScopeKey(scope, identifier)` through `cacheLiveScope`. After the merge, `handleNoStreamCache` writes **`chosen`** (PreferRemediation of IP plus every header) onto the client-address key `remoteIP` whenever the merged verdict is active.

```
LiveLookup(remoteIP, scopes, ttl)
  ├─ queryLiveDecisions ip=          → ipResult (clean "f" or IP ban/captcha)
  ├─ for each header:
  │    mergeLiveScope
  │      queryLiveDecisions scope=&value=
  │      cacheLiveScope(HeaderScopeKey)   [header slot — dest OK]
  │      chosen = PreferRemediation(chosen, header)
  └─ if IsActiveRemediation(chosen):
       cache.Set(remoteIP, chosen, …)     [IP slot — dest BUG when chosen is header-only]
```

Request lookup (`LookupCachedRemediation`) treats an active value on `remoteIP` as a hit **before** header keys. A later request from the same address with a different header therefore inherits the first identity's ban without another LAPI call.

`TestLiveLookup_ScopeBanWins` only asserts the first-call return. It does not read the IP slot.

Consumed: `knowledge/devdocs/index.md` (no `priority: always`), then `core_plugin_decisionscope.md`, `core_plugin_lapi_connection.md`, `core_plugin_ip.md`, `core_cache_client.md`, `core_plugin_middleware.md`. Research indexes: no new outside-world write — CrowdSec scope matching is already in `ext_crowdsec_decisions_scopes`; this defect is the in-tree IP-slot write. Language is enough; usage is enough to call the path. Do not document the intended IP-slot vs header-slot write until the code matches (devdocsimpact).

**Reproduced** (`go test ./pkg/lapi/ -run "TestHunt_LiveLookupDoesNotCacheHeaderBanOnIP|TestLiveLookup_ScopeBanWins" -count=1 -v`, throwaway `pkg/lapi/zzz_hunt_live_header_ban_ip_test.go` removed after the run; dest tree on this worktree):

- `TestLiveLookup_ScopeBanWins` — PASS (first-request return only).
- `TestHunt_LiveLookupDoesNotCacheHeaderBanOnIP` — FAIL at the IP-slot assertion: after a clean `?ip=` plus a Country ban `FR`, `cacheClient.Get("1.2.3.4")` returned `"t\x1fCAPI"` (ban letter plus unit-separator plus origin). The named hunt test is not on `origin/master`; this run recreated its assertion against `handleNoStreamCache`.

## Decisions

- Fix site is `handleNoStreamCache` after the scope loop: write the **IP query result** (`ipResult` / `chosen` before header merge) to `remoteIP`, not the merged `chosen`. Keep `cacheLiveScope` as the header-slot owner. Do not change `HeaderScopeKey`, `LookupCachedRemediation` merge order, or live TTL math.
- A clean IP query plus a remediating header writes `NoBannedValue` on the IP key (that is the IP query result). The request that just merged still returns the header ban. A later lookup for the same IP and a different header hits the clean IP slot and misses the other identity's `HeaderScopeKey`.
- An IP ban plus a header ban still writes the IP ban on the IP key (the IP query result). Header result stays on `HeaderScopeKey`.
- Captcha on a header is the same write (`IsActiveRemediation`). Do not split a captcha-only path.
- Spec: fold `core_plugin_decisions_scopes` (Ip keys stay exact-address). Dest already says that; dest code writes a header ban onto the IP key. Propose records the fold. No new leaf for one cache-slot write.
- Product test: dest-style name next to `TestLiveLookup_ScopeBanWins`. Assert IP slot is the IP query result **and** `LookupCachedRemediation` for the same IP plus a different header does not inherit the header ban. Do not land `TestHunt_*`.
- Usage packet `core_plugin_lapi_connection.md` names the IP-slot vs header-slot rule after the write matches (implement / `sbs-dev-devdocsimpact`). Explore does not rewrite dest-true usage into the intended contract.

## Open questions

- Q: Who already owns client address and header identity for this path?
  Decision: resolved — `pkg/ip.GetRemoteIP` owns the client address. `pkg/bouncer` stores it on `clientRequest.remoteIP` and passes that string into `LiveLookup`. `decisionscope.RequestScopeValues` owns header identity from `decisionScopeHeaders`. `handleNoStreamCache` consumes those outputs. Do not re-parse `RemoteAddr` or re-read headers in `pkg/lapi`. Traefik `RemoteAddr` is the socket peer, not this plugin's client-address owner. A peer library that walks `X-Forwarded-For` again is not the owner.
  By: explore

- Q: Should a clean IP query write `NoBannedValue` on the IP key when a header scope is remediating?
  Decision: resolved — yes. Ticket Desired: write the IP query result; a clean `?ip=` is `NoBannedValue`. Header remediations stay on `HeaderScopeKey`.
  By: explore

- Q: When both the IP query and a header query ban, what goes on the IP key?
  Decision: resolved — the IP query result (the IP ban). That is today's IP-key write when the IP itself is banned. Header result remains on `HeaderScopeKey`.
  By: explore

- Q: Fold `core_plugin_decisions_scopes` or open a new spec leaf?
  Decision: resolved — fold. FindSpecHost: `{ deltaId: live-ip-slot-holds-ip-query, fold, core_plugin_decisions_scopes, high }`. One added requirement on that leaf. Do not invent a sibling leaf for this write.
  By: propose

- Q: What product test name lands?
  Decision: resolved — `TestLiveLookup_IPSlotKeepsIPQueryResult` beside `TestLiveLookup_ScopeBanWins`. Assert the IP slot is the IP query result and `LookupCachedRemediation` for the same IP plus a different header does not inherit the header ban. Do not commit `TestHunt_LiveLookupDoesNotCacheHeaderBanOnIP`.
  By: propose

- Q: When does usage name the IP-slot vs header-slot write?
  Decision: assumed — after the code writes the IP query result (`core_plugin_lapi_connection.md` via implement / devdocsimpact). Explore does not document dest's merged write as the contract.
  By: explore
