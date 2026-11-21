# Delivery

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
