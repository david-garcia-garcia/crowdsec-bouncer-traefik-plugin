## Motivation
Operators who set `bouncerRemediationStatusCode: 429` want banned clients to be throttled rather than refused outright. Clients that honour 429 (API SDKs, well-behaved crawlers, retry middleware) look for `Retry-After` to decide when to come back. The plugin knows when each CrowdSec LAPI decision ends, because the decision arrives with a `Duration`.

A LAPI ban on such a router is answered 429 with no `Retry-After`. A stream-mode router with a 1h ban stored for the client returns `status=429`, and the only headers are `Cache-Control` and `Content-Type` (reproduced in explore). Each client has to guess: it comes back too early and hits the ban again, or it waits far longer than the decision lasts.

The end is not just missing from the response. It is lost before the response is written:
- `Store.LookupRemediation` and `LiveLookup` return kind and origin only.
- In live mode, the memory slot keeps the cache-entry expiry, which is capped at `lapiDefaultDecisionSeconds`. So even a cached ban cannot tell a 4h decision from a 60s cache entry.
- The shared Redis value (`kind\norigin\nscenario`) has no end at all, so an instance that reads another instance's write has nothing to report.

If nothing changes, every 429 ban on these routers stays a blind wait for the client, and the status code operators picked for throttling has nothing to tell clients when to come back.

Priority: P2 — real end-user and operator pain on routers set to 429, with limited blast radius (the default 403 is unaffected and clients can still retry on their own schedule)

## Implementation
The decision's time left is read where the decision is read, and it travels as one explicit value down the LAPI path only.

- **Store.** `Decision` gains `DecisionDurationSec`, separate from the store TTL `DurationSec`. Stream apply sets both to the CrowdSec duration. The live memo keeps the TTL capped by `liveCacheTTL` and passes the full LAPI duration as the decision duration. Memory `LiveSlot` grows from 8 to 12 bytes with `DecisionEnd` on the elapsed slot clock (0 = unknown). Redis writes the end as a 4th line in wall-clock Unix seconds after `scenario`, with empty origin and scenario lines kept as placeholders. The reader splits the text after the origin at its last newline and treats the tail as an end only when it is a positive integer, so a numeric 3-line scenario is never read as an end. Fork readers from v1.9.4 fold the extra line into the scenario, which their lookup never returns. Each engine turns the end into time left on its own clock at lookup. A missing or past end gives 0.
- **Merge.** `lookupHit` carries `decisionLeft`, so `mergeLookupHit` keeps the winner's end with no new rule (ban over captcha, first hit on a tie). A Range winner comes from the Range-index blob, which has no end, so it returns 0. `LiveLookup` returns the duration of the decision `preferLiveResult` kept.
- **Serve path.** `serveLAPI` takes `decisionLeft` from `LookupRemediation` or `LiveLookup`. It passes the value through `remediateUnderActionRules` → `handleRemediationServeHTTP` → `handleCaptchaKindServeHTTP` (downgrade ban) or `handleBanServeHTTP` → `handleBanStatusServeHTTP`. Every other caller passes the named zero `noLAPIDecisionEnd`: action-rule ban, captcha rule, LAPI/AppSec/ModSecurity failure actions, `banWarnCaptchaRule`, the AppSec ban verdict, and the AppSec captcha gate. The origin remap changes only the kind, so a remapped or bypassCaptcha-kept ban keeps its stored end.
- **Writer.** `handleBanStatusServeHTTP` sets `Retry-After` before `WriteHeader`, next to `Cache-Control`. It does so only when the status is 429 and `decisionLeft > 0`. The value is whole seconds rounded up, at least 1 (`retryAfterSeconds`). HEAD bans carry it without a body.
- **Deviation.** One deviation from the requirement was taken in explore: in live/none, LAPI expands Range on `?ip=` and returns the duration, so a Range ban there gets the header. Only stream/alone Range bans go without it.
- **Proof.** Unit tests:
  - `pkg/bouncer`: a header matrix across stream, live, HEAD, Range, captcha served as a ban, a challenge page, action rules, remap, bypassCaptcha, the failure, unhealthy-stream and cache-failure bans, and an AppSec `http_status` 429.
  - `pkg/decisionstore`: memory and Redis ends, plus Redis values without a usable end.
  - `pkg/lapi`: stream and live plumbing.

  Mock e2e adds 429 routers to the `stream-mode`, `live-mode` and `redis` scenarios. In `redis`, a canned 4-line value is used, and a bare `t` proves no header without an end. Real e2e extends `/status-429` and adds a stream 429 router (`config/dynamic/retry-after.yml`) with its own bouncer key. The AppSec `RateLimit()` 429 test now asserts no `Retry-After`.
- **Docs.** README, devdocs and spec deltas are updated. Two follow-ups are filed as debt notes: the origin id that `LookupRemediation` returns is always 0, and `map.md` lacks `wafhop`.

## What this changes
**Operators.** On a router with `bouncerRemediationStatusCode: 429`, LAPI bans now send `Retry-After`. Shared Redis slot values gain a fourth end line that v1.9.4+ instances still read. The value can be off by the clock skew between instances. Memory-store RAM grows with the 12-byte slot (about 26.7 → 33.7 MB at 400k decisions).
**Admin users.** None.
**Developers.** `Store.LookupRemediation` and `lapi.Client.LookupRemediation` now return `(kind, origin, originID, decisionLeft, err)`, and `LiveLookup` returns `(kind, origin, decisionLeft, err)`. `decisionstore.Decision` gains `DecisionDurationSec` apart from the TTL `DurationSec`. `LiveSlot` gains `DecisionEnd`, and `LiveSlotFromPack` takes the decision duration.
**End users.** A client banned by a LAPI decision on a 429 router now gets `Retry-After` with the seconds left on that decision. A 403 ban, an AppSec ban, a failure ban, an action-rule ban and a stream/alone Range ban stay without it.

## Merge readiness
Ready for review. 1 items remain.

Priority: P2 — real end-user and operator pain on routers set to 429, with limited blast radius (the default 403 is unaffected and clients can still retry on their own schedule)
Reviewed head: 85300168
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Ready |
| CI proof | 6/6 | succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/commit/524684821d4563f808dc816d7055a5eb9817ec17/checks |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-11-21-lapi-ban-retry-after pushed | `git` |
| OpenSpec | lapi-ban-retry-after | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/229 | pr-host |
| CI | build 44942342228 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/commit/524684821d4563f808dc816d7055a5eb9817ec17/checks | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/commit/524684821d4563f808dc816d7055a5eb9817ec17/checks |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_decisions_scopes](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-21-lapi-ban-retry-after/openspec/changes/lapi-ban-retry-after/proposal.md) — modified
- [core_plugin_decisionstore_store](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-21-lapi-ban-retry-after/openspec/changes/lapi-ban-retry-after/proposal.md) — modified
- [core_plugin_lapi_stream-apply](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-21-lapi-ban-retry-after/openspec/changes/lapi-ban-retry-after/proposal.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-21-lapi-ban-retry-after/openspec/changes/lapi-ban-retry-after/proposal.md) — modified


## Deviations from the ask
- taken: decision 4 — "Range-scope bans carry no `Retry-After` in this change (the Range-index blob has no end)". → stream/alone Range bans (served from the Range-index blob) carry no header. In live/none, LAPI expands Range on the `?ip=` query and returns the decision with its `Duration`, so that ban carries `Retry-After` like any other LAPI ban answered 429. — `pkg/lapi/client_decisions.go (queryLiveDecisions parses the chosen decision's duration whatever its scope)` — decision 4's reason is the blob, which only stream/alone read. Following the letter in live/none would add a scope check to `queryLiveDecisions` only to hide an end it already knows.. Requester: not asked.


## Follow-up issues
- [ ] [`LookupRemediation` origin id is always 0](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-21-lapi-ban-retry-after/knowledge/debt/2026-11-21-lookup-remediation-origin-id-always-zero.md) — `Store.LookupRemediation` always returns origin id 0 although the catalog promises it; callers lean on the origin name.


## How this fits together
Ticket 2026-11-21-lapi-ban-retry-after on branch 2026-11-21-lapi-ban-retry-after targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/229; CI build 44942342228 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/commit/524684821d4563f808dc816d7055a5eb9817ec17/checks.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Does a LAPI captcha decision answered as a ban (unsubscribed captcha, unusable captcha client, remap, HEAD) carry `Retry-After`? | additive asked — passes an existing decision end to a branch that already exists; decision 7 names "unsubscribed captcha served as ban" | assumed — yes, when the status is 429. It is still a LAPI decision with a known end, and the response is a ban. This covers `handleCaptchaKindServeHTTP` downgrade reached from `serveLAPI` (unsubscribed or unusable client). The remap has no edge to ban (`pkg/configuration/origin_based_decision_remap.go:44`). A bypassCaptcha request that keeps a stored ban the remap would turn into a captcha keeps that ban's own end. HEAD: a usable captcha serves the challenge on HEAD (not a ban, no header). A HEAD ban carries the header with no body. | explore |


## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-21-lapi-ban-retry-after/devstate/staging/2026/11/2026-11-21-lapi-ban-retry-after/codereview_standards.md) — 3 total, 0 pending, 1 completed, 2 skipped
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-21-lapi-ban-retry-after/devstate/staging/2026/11/2026-11-21-lapi-ban-retry-after/codereview_nitpicks.md) — 1 total, 0 pending, 1 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-21-lapi-ban-retry-after/devstate/staging/2026/11/2026-11-21-lapi-ban-retry-after/codereview_spec.md) — 2 total, 0 pending, 1 completed, 1 skipped
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-21-lapi-ban-retry-after/devstate/staging/2026/11/2026-11-21-lapi-ban-retry-after/codereview_scope.md) — 1 total, 0 pending, 0 completed, 1 skipped
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-21-lapi-ban-retry-after/devstate/staging/2026/11/2026-11-21-lapi-ban-retry-after/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-21-lapi-ban-retry-after/devstate/staging/2026/11/2026-11-21-lapi-ban-retry-after/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-21-lapi-ban-retry-after/devstate/staging/2026/11/2026-11-21-lapi-ban-retry-after/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-21-lapi-ban-retry-after/devstate/staging/2026/11/2026-11-21-lapi-ban-retry-after/codereview_coverage.md) — 1 total, 0 pending, 0 completed, 1 skipped


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 4 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 853001686e2d027cde606ede52fc813753de5cdc | Card must match the branch you measured |

### Stored data model
- **Redis** (shared decision store), Ip and header-scope slot value (key `<prefix><ip>` / `<prefix><scope:value>`), field **decision end** — **added** as a 4th newline-separated line after kind, origin, scenario: wall-clock Unix seconds, written by `redis.PutMany` as `now.Unix() + DecisionDurationSec` when that duration is positive (stream apply and live memo both set it); empty origin/scenario lines are kept as placeholders (`t\n\n\n<end>`). With no end the value is byte-identical to before. Key names, TTL (`msetexGrouped` by `DurationSec`) and the `range-index` blob (`KindOriginString(..., 0)`) are unchanged (`pkg/decisionstore/redis_pack.go`, `pkg/decisionstore/redis.go`). migration: missing — no migration artifact in the pin; none deploys this field: the new reader treats values without a usable end as unknown and old values expire by TTL (`openspec/changes/lapi-ban-retry-after/design.md`, Migration Plan).
  - Rollback, previous reader (`.pin_diff/base/pkg/decisionstore/redis_pack.go`, v1.9.4–v1.9.7 shape): `strings.Cut` for kind, then `strings.Cut` for origin, the rest is the scenario. On a 4-line value kind and origin come out correct, and the end is folded into `scenario` (`ssh-bf\n<end>`, or `\n<end>` when the scenario is empty). Base `lookupHits` returns only kind and origin (`.pin_diff/base/pkg/decisionstore/lookup.go`), so that scenario is never used. Stays correct.
  - Rollback, one-cut reader (`splitKindOrigin` in `pkg/decisionstore/pack.go` at tag v1.9.3, confirmed by the caller with `git grep` on that tag): the kind stays correct (`RemediationKind` of the first line), and the origin becomes everything after the kind. That already happens for every 3-line value. New on top of that: a decision that used to be stored as `t` or `t\n<origin>` (no scenario) now carries an end too, so this reader gets a polluted origin where before it read it correctly or as empty. This affects only the origin, not the kind. It is not a red flag under `opd-redflags` (nothing removed, renamed or retyped).
