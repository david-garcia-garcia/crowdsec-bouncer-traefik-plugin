# Design

## Context

See proposal.md (Why) and the run's `explore.md` (every caller of the ban writer, the stored formats, benchmark baseline).

Today the decision end is lost at three places:

- `Store.LookupRemediation` returns kind, origin, and origin id. The memory slot (`LiveSlot{Word, ExpiresAt}`) has an expiry, but in live mode that expiry is the capped cache end, not the decision end. The Redis value (`kind\norigin\nscenario`, written since #178) has no end at all.
- `LiveLookup` parses the chosen decision's `Duration` into `liveResult.duration`, uses it for `liveCacheTTL`, and returns only kind and origin.
- `handleBanStatusServeHTTP` writes every ban (LAPI, AppSec, ModSecurity, failure actions, cache failure, action rules, captcha downgrade) and knows nothing about the decision behind it.

The catalog still says Redis slots are `KindOriginString` (two lines) and pins `LiveSlot` at 8 bytes. The spec deltas restate the real value, with the new end line.

## Goals / Non-Goals

**Goals:**

- The time left on the decision the lookup chose reaches the ban writer only on LAPI paths.
- One place decides whether `Retry-After` is written: the ban writer, from the status it writes and the time left it was given.
- A Redis value with an end stays readable by fork versions from v1.9.4 on.

**Non-Goals:**

- No end in the Range-index blob. Stream/alone Range bans keep no header.
- No change to the live cache TTL (`liveCacheTTL` and the `lapiDefaultDecisionSeconds` cap stay).
- No `Retry-After` on statuses other than 429 (503 included), on captcha pages, or on AppSec and ModSecurity answers.
- No change to which decision wins (`mergeLookupHit`, `strongestLiveDecision`, `preferLiveResult`).

## Decisions

### 1. The time left travels as one explicit parameter down the LAPI path

`serveLAPI` gets the time left from `LookupRemediation` (store hit) or `LiveLookup` (live/none miss). It passes it to `remediateUnderActionRules`, then `handleRemediationServeHTTP`, then `handleCaptchaKindServeHTTP` (downgrade ban) or `handleBanServeHTTP`, then `handleBanStatusServeHTTP`. Each of these functions gains one `decisionLeft time.Duration` parameter. Every other caller passes the named zero `noLAPIDecisionEnd`: the action-rule ban (`bouncer.go`), the captcha rule (`applyCaptchaRuleServeHTTP`), the LAPI failure action `captcha` (`applyLapiFailureAction`), the AppSec and ModSecurity failure action `captcha`, the AppSec ban verdict with its `http_status` (`handleBanStatusServeHTTP`), and the AppSec captcha gate. `banWarnCaptchaRule` keeps its signature: no LAPI decision is behind any of its callers (cache failure, LAPI, AppSec, and ModSecurity failure bans, and `banAppsecVerdict`), so it passes `noLAPIDecisionEnd` itself. `appliedLAPIRemediation` maps only the kind. The time left of the stored decision goes through unchanged, so a remapped ban that ends as a downgrade ban, or a ban kept on a bypassCaptcha request, keeps its own end.

Alternatives:

- Set `Retry-After` on `rw` in `serveLAPI` before dispatch. Rejected in explore: it would leak onto a captcha challenge, onto a pass-through (cleared gate, bypassCaptcha), and onto a later AppSec or ModSecurity answer.
- A value type for kind, origin, and time left. Rejected: the cluster does not hold below `handleRemediationServeHTTP`. The writer takes reason, header reason, origin, and status, not kind. Four of the five `handleRemediationServeHTTP` production callers would build the type only to pass constants.
- A flag on `clientrequest.Request`. Rejected: the inbound request is not where per-leg remediation state lives (`core_plugin_middleware_action-rules.md`), and a later leg would read it by accident.

### 2. The ban writer owns the header rule

`handleBanStatusServeHTTP` sets `Retry-After` next to `Cache-Control`, before `WriteHeader`, only when `statusCode == http.StatusTooManyRequests` and `decisionLeft > 0`. The value is the time left in whole seconds, rounded up (`retryAfterSeconds`), which is at least `1` for any positive time left (RFC 9110 §10.2.3 delay-seconds). An AppSec ban with `http_status` 429 reaches the writer with `noLAPIDecisionEnd`, so the status check alone never adds the header. HEAD and a nil template still get the header, as `Cache-Control` does today.

### 3. Store and Client lookups return the time left as an extra value

`Store.LookupRemediation`, the engine `lookup` func, `memory.LookupRemediation`, `redis.LookupRemediation`, and `lapi.Client.LookupRemediation` return `(kind, origin, originID, decisionLeft, err)`. `LiveLookup` returns `(kind, origin, decisionLeft, err)`. Zero means unknown. Each engine computes the time left on its own clock at lookup time, so no caller handles an elapsed-clock or Unix value.

Alternative: one result struct. Rejected: the single production caller destructures at once, both lookups already return tuples, and LiveLookup's error meaning (`active kind + error` = a real decision) stays as it is. Yaegi: the engine stays a struct of funcs; no interface holds a map; `time.Duration` is a plain integer type.

### 4. The merge keeps the winner's end because the end is on the hit

`lookupHit` gains `left time.Duration`. `mergeLookupHit` already keeps the whole winning hit (ban over captcha, first hit on a tie), so its end follows without a second rule. `lookupHits` returns `(kind, origin, left)`. A Range hit comes from the blob, which has no end, so a Range winner returns zero even when the Ip slot held a captcha with an end.

### 5. Memory: `LiveSlot.DecisionEnd` on the elapsed clock

`LiveSlot` becomes `{Word uint32, ExpiresAt int32, DecisionEnd int32}`, 12 bytes (approved). `DecisionEnd` uses the elapsed slot clock with the same saturation as `expiryFromDuration`. `0` means unknown, and a known end is always ≥ 2 because of `elapsedBias`. `Decision` gains `DecisionDurationSec int64`, the decision's remaining duration, apart from `DurationSec` (the store TTL). Stream apply sets both to the parsed duration, so for stream `DecisionEnd == ExpiresAt`. Live/none memo sets `DurationSec = liveCacheTTL(...)` and `DecisionDurationSec` from the full LAPI duration. A non-positive decision duration (and every `f` memo) gives `DecisionEnd = 0`. Lookup turns `DecisionEnd - elapsedNow()` into a duration. A slot that has not expired always has an end later than now, because `ExpiresAt <= DecisionEnd`.

Alternative: a side map of live decision ends next to the slot map. Rejected in explore: a second copy-on-write map with its own expiry next to the single owner.

### 6. Redis: the end is the 4th line, in wall-clock Unix seconds

The Redis codec takes and returns the end separately from the hit: `packToString(hit, endUnix)` and `unpackFromString(stored) (hit, endUnix)`. `KindOriginString` and the Range blob pass and ignore `0`, so the Range index is unchanged. `PutMany` writes `endUnix = now.Unix() + DecisionDurationSec` when the decision duration is positive. Then it writes all four lines: `kind\norigin\nscenario\nend`, with empty origin or scenario lines kept as placeholders. With no end, the value is the same as today. The reader cuts kind, then origin. It then splits the rest at its **last** newline. The tail is the end when it parses as a positive integer; otherwise there is no end and the rest is the scenario. `redis.LookupRemediation` returns `time.Until(time.Unix(endUnix, 0))`, and a non-positive result means unknown. The wall clock is required because the value is shared across processes, and the elapsed clock is per process.

Splitting at the last newline keeps a 3-line value whose scenario is a number from being read as an end: the rest after the origin line has no newline. It also keeps a scenario that contains a newline in the scenario.

Alternatives: milliseconds (upstream's `t;<unix ms>`). Rejected: out of scope, and the header has whole-second resolution. An end before the scenario. Rejected: v1.9.4–v1.9.7 readers would put the end into the scenario field and the real scenario after it. Only the order chosen here keeps their kind and origin correct with no change.

### 7. Live: the winner's duration is the time left

`queryLiveDecisions` already parses the chosen decision's `Duration`, and `preferLiveResult` already keeps the winner's duration. `handleNoStreamCache` returns `chosen.duration` with an active kind (≤ 0 becomes zero). `memoLive` and `cacheLiveScope` pass `int64(duration.Seconds())` as `DecisionDurationSec` next to the capped TTL. `strongestLiveDecision` keeps picking the first ban LAPI lists, which can have a shorter end than another ban. That is accepted (requirement decision 5): a short value only brings the client back early.

### 8. Test and e2e placement

- Unit tests sit next to the code they cover: `pkg/decisionstore` (pack/unpack, memory stream and live end, Redis 4-line value, old-format and garbage ends, merge winner, 12-byte size assert), `pkg/lapi` (stream and live plumbing, `LiveLookup` return), and `pkg/bouncer` (header matrix).
- Mock e2e: add a 429 middleware and router to `stream-mode` and `live-mode`, and assert `Retry-After` in `1..duration` (`mocklapi` returns the stored duration verbatim). In `redis`, add a 4-line canned value with an end computed per request for a new IP. The existing `t` value for `1.2.3.5` proves that a value without an end gets no header. A range-assert helper goes into `lib/common.sh` beside `assert_header`.
- Real e2e: extend the existing `/status-429` test (none mode, `Add-TestDecision` default 1h → `1..3600`) and add a no-header assertion on a 403 route. For stream, add a file-provider router `config/dynamic/retry-after.yml` with `lapiMode: stream` and `bouncerRemediationStatusCode: 429`, on its own bouncer key registered on the crowdsec service (`BOUNCER_KEY_RETRY_AFTER_STREAM`). Assert it in `mode_stream.Tests.ps1`. Add a no-`Retry-After` assertion to the existing AppSec `RateLimit()` 429 test. A new router is safer than reusing the instance-severance T5 subscriber: that suite tears instances down on purpose.

## Risks / Trade-offs

- [Memory: 50 % more map storage per decision (400k: about 26.7 → 33.7 MB with keys); a 100k clone goes from 3.4 to about 4.3 ms] → Approved by the requester. Re-run the explore benchmarks and update the `memory_pack.go` comment table with measured numbers.
- [Replica clock skew on Redis: the header can be off by the skew between the writing and the reading replica] → Accepted and documented. An end that is already past on the reading replica gives no header, never a negative or zero value.
- [Mixed-version window: values written by an older instance have no end] → No header for them until the key expires (at most the decision duration in stream, `lapiDefaultDecisionSeconds` in live). Documented in the README.
- [A long decision (CAPI or a list, days) tells clients to wait days] → That is the decision's real remaining time, and it is what the header is for.
- [`handleBanServeHTTP` and `handleRemediationServeHTTP` signatures change for 5 + 5 test callers] → Mechanical; the tests pass `noLAPIDecisionEnd` unless they assert the header.

## Migration Plan

No data migration. Values keep their key names and TTLs, and new values add one line.

- Deploy: new instances write the 4th line. Old values are read with no end until they expire.
- Rollback to v1.9.4–v1.9.7: their reader (`strings.Cut` twice, checked at tags v1.9.4, v1.9.5, v1.9.6, and v1.9.7) reads the kind and origin lines correctly and folds the end into the scenario. Their lookup never returns the scenario (`lookupHits` returns kind and origin at v1.9.7). Bans stay bans, origins stay correct.
- Rollback to v1.9.3 or older: their reader (`splitKindOrigin`, one cut) puts every line after the kind into the origin. That has been true for every 3-line value since v1.9.4. The kind stays correct. This change widens that gap: a decision with no scenario (`t`, or `t` and an origin line), which v1.9.3 read cleanly, now carries an end line, so v1.9.3 reads a wrong origin label for it too. Only the metrics origin label is affected, never the kind.
- Memory slots are process memory and do not survive a restart.

Red flags (`opd-redflags`): none. The Redis change is a compatible addition, and no field is removed, renamed, or retyped. The memory slot is process memory. No `redflags.md` row.
