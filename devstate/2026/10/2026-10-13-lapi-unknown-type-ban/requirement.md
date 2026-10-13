# Requirement
IssueKey: 2026-10-13-lapi-unknown-type-ban

## Problem
A LAPI or blocklist decision whose type is neither `ban` nor `captcha` (for example `challenge`) is not stored as a ban. Stream mode then treats the IP as unknown and allows it. CrowdSec's challenge protocol and lua-cs-bouncer fail closed to ban for unsupported decision types.

## Current (code)
- Stream ingest `handleStreamCache` in `bouncer.go`: `switch decision.Type` maps `ban` → `cache.BannedValue`, `captcha` → `cache.CaptchaValue`; `default` logs Info `handleStreamCache:unknownType` and leaves `value` empty, then `cacheClient.Set`.
- Local cache miss for empty payload: `pkg/cache/cache.go` `localCache.get` returns `CacheMiss` when the stored string length is 0. Redis get does the same.
- Stream serve `ServeHTTP` in `bouncer.go`: cache miss with a healthy stream calls `handleNextServeHTTP` (allow).
- Live/none ingest `handleNoStreamCache` in `bouncer.go`: same type switch; `default` logs Info and leaves `value` empty; returns that value with `handleNoStreamCache:banned`. Empty decision list (`len == 0` or JSON `null`) returns `cache.NoBannedValue` without that error.
- Live/none serve `ServeHTTP` in `bouncer.go`: any value other than `cache.NoBannedValue` (including empty) calls `handleRemediationServeHTTP`, which bans unless the value is captcha. Live then `Set`s the empty string, so the next Get is a miss and the query repeats.
- `decisionscope.RemediationValue`, `streamPutItem`, `strongestLiveDecision`, `queryLiveDecisions`: not found on dest (`origin/main`).

## Desired
- A stream or live (and none, which shares `handleNoStreamCache`) LAPI decision whose type is neither `ban` nor `captcha` (for example `challenge`, and `allow`) is stored and applied as a ban.
- Log the unknown type at the existing log site (`handleStreamCache:unknownType`).
- Do not change a mapper whose empty result means "not a remediation code" for other callers (on dest there is no `RemediationValue`; fail-closed stays at the two ingest switches).
- Do not ban an empty decision list.

## Affected
- `bouncer.go` `handleStreamCache` (stream New)
- `bouncer.go` `handleNoStreamCache` (live and none)
- Tests next to those paths (`bouncer_test.go`)

## Out of scope
- AppSec `action: challenge` relay
- Metrics
- Captcha provider
- Other points of upstream PR 403 (unexpected AppSec status, AppSec captcha, challenge-path 404, blocked-request counting, README)

## Unknowns
- Exact lua-cs-bouncer fallback table and CrowdSec challenge-protocol wording (explore).
- Whether dest live already applying empty as a ban is enough, or the cache must store `cache.BannedValue` so later Gets stay bans (ticket: stored and applied).

## Tensions
- Ticket names `decisionscope.RemediationValue` / `streamPutItem` / `strongestLiveDecision` / `queryLiveDecisions` and a throwaway test (`ok=false kind=""`). Those units are not on dest; dest ingest is the two switches in `bouncer.go`.
- Ticket says the log is Debug; dest logs Info at the same message.
- Ticket says live ignores unknown types; dest live remediates empty as ban on the first query, then caches a miss.
