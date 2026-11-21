# Requirement
IssueKey: 2026-11-21-lapi-ban-retry-after

## Problem
Human ask (2026-11-21, chat): "could we add retry-after for banned lapi bans? https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/439".

With `bouncerRemediationStatusCode: 429`, a ban from a LAPI decision is answered 429 with no `Retry-After`, so clients that honour 429 cannot know when to come back, although the decision's end is known. Upstream proposes the header in maxlerebourg/crowdsec-bouncer-traefik-plugin#439 (open, not merged; read 2026-11-21). Upstream's code layout (`pkg/cache`, root `bouncer.go`) does not exist in this fork; this fork implements it on its own units, independently of #439 merging (decision 6).

Decisions taken with the human in chat (2026-11-21), carried verbatim in `ticket/source.md`:
1. `Retry-After` only when the final response is a ban that comes from a LAPI decision with a known end AND the status written is 429. None with 403 or other codes, none on AppSec bans (including AppSec `http_status` 429), none on technical / failure-action bans (LAPI unreachable, cache/Redis failure, unhealthy stream).
2. Live mode reports the real remaining time of the decision, not the cache-entry TTL (capped at `defaultDecisionSeconds`). Approved: memory `LiveSlot` grows from 8 to 12 bytes (a decision-end field); this changes the devdocs rule that LiveSlot stays 8 bytes.
3. Redis carries the decision end as an extra field in the stored value, so it survives cache hits across instances; previous fork versions must still read it (rolling upgrade / rollback safe).
4. Range-scope bans carry no `Retry-After` in this change (the Range-index blob has no end); the README says so.
5. Several hits: use the end of the decision that produced the ban.
6. Implement now in this fork; full opd-workflow run; PR to `master`; unit, e2e mock, and real e2e coverage for 429 + `Retry-After` where the existing suites allow.
7. Correct with `bouncerActionRules` (captcha→ban, bypassCaptcha), origin-based decision remap, and unsubscribed captcha served as ban; README documents the header next to `bouncerRemediationStatusCode`.

## Current (code)
- Ban write: `pkg/bouncer/bouncer_serve_remediation.go` `handleBanStatusServeHTTP` sets the remediation header, `Content-Type`, `Cache-Control`, then `WriteHeader(statusCode)`; no `Retry-After`. `handleBanServeHTTP` passes `b.remediationStatusCode`. Shared by LAPI bans, failure actions, cache-failure bans, captcha downgrade, and action-rule bans.
- LAPI serve: `pkg/bouncer/bouncer_serve_lapi.go` `serveLAPI` — stream/alone/live call `lapiClient.LookupRemediation` (returns kind, origin, originID, err; no end); live/none miss calls `lapiClient.LiveLookup` (returns kind, origin, err; no end). Failure paths go through `applyLapiFailureAction` / `banWarnCaptchaRule`.
- Remediation dispatch: `pkg/bouncer/bouncer_serve_remediation.go` `handleRemediationServeHTTP`; action rules in `pkg/bouncer/bouncer_serve_captcha.go` `remediateUnderActionRules` (bypassCaptcha returns false) and `banWarnCaptchaRule`.
- Unsubscribed / unusable captcha served as ban: `pkg/bouncer/bouncer_serve_captcha.go` `handleCaptchaKindServeHTTP` → `handleBanServeHTTP` with `headerReasonCaptchaDowngrade`.
- Origin remap: `pkg/bouncer/origin_based_decision_remap.go` `appliedLAPIRemediation` (kind remap per origin; a bypassCaptcha request keeps a ban the remap would soften).
- AppSec ban status: `pkg/bouncer/bouncer_serve_appsec.go` `applyAppsecServeHTTP` (an AppSec ban keeps CrowdSec `http_status`, which can be 429; `README.md` `BouncerRemediationStatusCode` entry).
- Live lookup: `pkg/lapi/client_live.go` `handleNoStreamCache` memoizes the IP result with `liveCacheTTL(duration, defaultDecisionSeconds)`; `pkg/lapi/client_decisions.go` `queryLiveDecisions` parses the picked decision's `Duration` into `liveResult.duration`; `strongestLiveDecision` picks the first ban, else the first captcha; `preferLiveResult` keeps the winner's duration; `liveCacheTTL` = min(decision duration, `defaultDecisionSeconds`).
- Stream apply: `pkg/lapi/client_decisions.go` `streamPutItem` / `storeStreamDecision` put `decisionstore.Decision{…, DurationSec}`; Range scope is skipped there (Range goes to the range index).
- Memory slot: `pkg/decisionstore/liveslot.go` `LiveSlot{Word uint32, ExpiresAt int32}`; `ExpiresAt` is elapsed seconds on the package clock (`elapsedNow`), set from `DurationSec` (`expiryFromDuration`). `pkg/decisionstore/memory.go` `LookupRemediation` unpacks only `slot.Word` (kind, origin, originID).
- Redis value: `pkg/decisionstore/redis_pack.go` `packToString` writes `kind\norigin\nscenario`; `unpackFromString` cuts kind, then origin, then the rest as scenario. `pkg/decisionstore/redis.go` `PutMany` uses MSetEX with TTL = `DurationSec`; `LookupRemediation` returns kind and origin only (scenario unused on the lookup path, verified in `pkg/decisionstore/lookup.go` `lookupHits`).
- Range index: `pkg/decisionstore/range.go` (`ApplyRangeIndex`; records of cidr/kind/origin, no end); Redis key `range-index` with a 365-day TTL (`pkg/decisionstore/redis.go` `rangeIndexTTL`).
- Store API: `pkg/decisionstore/store.go` `Store.LookupRemediation` (kind, origin, originID, err); `pkg/lapi/client_lookup.go` `Client.LookupRemediation` forwards it.
- Devdocs rule: `knowledge/devdocs/core_plugin_decisionstore.md` lines 26 and 48 ("`LiveSlot` stays `{uint32,int32}` (8 bytes)", "eight-byte `{uint32,int32}` slots").
- README: `README.md` `**BouncerRemediationStatusCode**` entry (~line 1119) and remediation table row `ban` (~line 143); `Retry-After` mention: not found.
- e2e mock: `tests/e2e/mock/scenarios/` has `stream-mode`, `live-mode`, `none-mode`, `redis`, and others; a scenario that sets `bouncerRemediationStatusCode`: not found (grep over `tests/e2e` hits only real-suite files).
- Real e2e: `tests/e2e/real/simple-bouncer.Tests.ps1`, `appsec.Tests.ps1`, `instance_severance.Tests.ps1`, `config/docker-compose.test.yml` reference the remediation status code; a 429 LAPI-ban router with a `Retry-After` assertion: not found.

## Desired
- A ban answered 429 (`bouncerRemediationStatusCode: 429`) that comes from a LAPI decision with a known end carries `Retry-After` = seconds left on that decision, rounded up, at least 1 (decision 1; rounding and minimum as in upstream #439).
- No `Retry-After` when the written status is not 429, on AppSec bans (any status), on failure-action / technical bans (LAPI unreachable, cache/Redis failure, unhealthy stream), and on Range-scope bans (decisions 1, 4).
- stream/alone: end from the stored decision (memory slot or Redis value).
- live: a cached ban reports the decision's real end, not the cache-entry end; memory `LiveSlot` gains a decision-end field (12 bytes, decision 2).
- live/none miss: end of the decision that produced the ban (decision 5).
- Redis value carries the end as an extra field; previous fork versions keep reading kind and origin correctly (decision 3).
- Correct under `bouncerActionRules` (captcha→ban, bypassCaptcha), origin-based decision remap, and unsubscribed captcha served as ban (decision 7).
- README documents the header next to `bouncerRemediationStatusCode`, including the Range exception.
- Unit tests; e2e mock and real e2e coverage for 429 + `Retry-After` where the suites allow (decision 6).
- Devdocs rule on the LiveSlot size updated to match (decision 2).

## Affected
- `pkg/bouncer/bouncer_serve_remediation.go`, `pkg/bouncer/bouncer_serve_lapi.go`, `pkg/bouncer/bouncer_serve_captcha.go`, `pkg/bouncer/origin_based_decision_remap.go` (read path)
- `pkg/lapi/client_live.go`, `pkg/lapi/client_decisions.go`, `pkg/lapi/client_lookup.go`
- `pkg/decisionstore/liveslot.go`, `memory.go`, `memory_pack.go`, `redis.go`, `redis_pack.go`, `lookup.go`, `store.go`, `decision.go`
- Unit tests in `pkg/bouncer`, `pkg/lapi`, `pkg/decisionstore`
- `tests/e2e/mock/scenarios/` (stream/live/none/redis), `tests/e2e/real/` (a Pester suite and `config/`)
- `README.md`
- `knowledge/devdocs/core_plugin_decisionstore.md`; likely `knowledge/devdocs/core_plugin_middleware_ban-page.md` and the catalog spec(s) for the ban response under `openspec/specs/`

## Out of scope
- `Retry-After` on AppSec bans (AppSec sends no time), including AppSec `http_status` 429.
- `Retry-After` on statuses other than 429.
- Adding an end to the Range-index blob / Range bans.
- `Retry-After` on captcha challenge pages, ModSecurity, or the rate-limiter leg.
- Copying upstream #439's patch or cache format (`t;<unix ms>`); its layout does not exist here.
- Changing the live cache TTL policy (the `defaultDecisionSeconds` cap stays).

## Unknowns
- Whether a captcha decision served as a ban (unsubscribed captcha, unusable captcha client, captcha→ban action rule, remap to ban, HEAD) carries `Retry-After`: decision 1 says "a ban that comes from a LAPI decision with a known end"; upstream #439 includes captchas only when no captcha provider is set. Explore decides per path.
- An action-rule ban not backed by a LAPI decision has no end, so presumably no header; confirm against decisions 1 and 7.
- Clock for the Redis end field: memory uses the per-process elapsed clock, which is not shareable; Redis needs wall time, so replicas can disagree by clock skew (upstream notes the same). Precision (seconds vs ms) and field position after `scenario` are open.
- Backward read: an older `unpackFromString` folds the extra field into `scenario` (`strings.Cut` on the rest). Fine for lookup per decision 3, but any other reader of a Redis `scenario` must be checked.
- How decision 5 resolves when the winning ban comes from a header scope while the IP slot holds a captcha (and the reverse), across memory, Redis, and live.
- Memory footprint and benchmark effect of the 12-byte `LiveSlot` on large stream sets (`pkg/decisionstore/zzz_lookup_bench_test.go`, `zzz_activecount_bench_test.go`).
- Whether the mock LAPI (`tests/e2e/mock/mocklapi`) returns durations precise enough to assert a header value range; whether the real suite can add a 429 router without disturbing other routers.
- Mixed-version window: values written by an older instance carry no end, so a newer reader sends no header for them (upstream has the same gap).

## Tensions
- `knowledge/devdocs/core_plugin_decisionstore.md` says `LiveSlot` stays 8 bytes; decision 2 (human-approved) grows it to 12.
- Decision 4 (no header on Range bans) vs the generic ask "retry-after for banned lapi bans": Range bans are LAPI bans that stay without the header.
- Upstream #439 takes the latest end among blocking decisions in live/none; decision 5 takes the end of the decision that produced the ban.
- `handleBanStatusServeHTTP` is shared by LAPI, failure-action, technical, and action-rule bans; the header must reach only the LAPI-decision path (decision 1).
