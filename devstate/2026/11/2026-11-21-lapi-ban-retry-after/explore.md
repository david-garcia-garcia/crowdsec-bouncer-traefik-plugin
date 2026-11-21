# Explore

## Concepts

### Units this change touches

| Unit | Path | Job today |
|------|------|-----------|
| Ban writer | `pkg/bouncer/bouncer_serve_remediation.go` `handleBanStatusServeHTTP` | Sets remediation header, `Content-Type`, `Cache-Control`, then `WriteHeader(statusCode)`. Every ban goes through it (LAPI, AppSec, ModSec, failure actions, tech bans, action rules, captcha downgrade). |
| Remediation dispatch | same file, `handleRemediationServeHTTP` / `handleBanServeHTTP` | Ban or captcha by kind; `handleBanServeHTTP` forwards `remediationStatusCode`. |
| Captcha dispatch | `pkg/bouncer/bouncer_serve_captcha.go` `handleCaptchaKindServeHTTP`, `remediateUnderActionRules`, `banWarnCaptchaRule` | Challenge, or downgrade ban when captcha is unsubscribed or unusable; bypassCaptcha returns false. |
| LAPI leg | `pkg/bouncer/bouncer_serve_lapi.go` `serveLAPI` | Store lookup (stream/alone/live), then `LiveLookup` (live/none miss); failure paths call `applyLapiFailureAction` / `banWarnCaptchaRule`. |
| Origin remap | `pkg/bouncer/origin_based_decision_remap.go` `appliedLAPIRemediation` | Weakens only: ban→captcha/pass, captcha→pass (`pkg/configuration/origin_based_decision_remap.go:44`). No edge leads to ban. On a bypassCaptcha request, a ban the remap would turn into a captcha stays a ban. |
| Live lookup | `pkg/lapi/client_live.go` `handleNoStreamCache`; `pkg/lapi/client_decisions.go` `queryLiveDecisions`, `strongestLiveDecision`, `preferLiveResult`, `memoLive`, `liveCacheTTL` | Parses the chosen decision's `Duration` into `liveResult.duration`; memo TTL = min(duration, `defaultDecisionSeconds`). |
| Stream apply | `pkg/lapi/client_decisions.go` `streamPutItem` | `Decision{…, DurationSec}`; Range skipped (goes to the Range blob). |
| Store API | `pkg/decisionstore/store.go` `Store.LookupRemediation`; `pkg/lapi/client_lookup.go` | Returns (kind, origin, originID, err). |
| Merge | `pkg/decisionstore/lookup.go` `lookupHits` / `mergeLookupHit` | Ban over captcha, first hit wins a tie; Range is merged only when the IP or header hits are not already a ban. |
| Memory slot | `pkg/decisionstore/liveslot.go` `LiveSlot{Word uint32, ExpiresAt int32}`, `elapsedNow`, `expiryFromDuration`; `memory.go`, `memory_pack.go` | ExpiresAt is in elapsed seconds (`elapsedBias` = 2 keeps 0 free as a sentinel). Stream: ExpiresAt = decision end. Live: ExpiresAt = capped cache end. |
| Redis value | `pkg/decisionstore/redis_pack.go` `packToString` / `unpackFromString`; `redis.go` `PutMany` (MSetEX TTL = `DurationSec`), `LookupRemediation` | `kind\norigin\nscenario` (scenario since #178, v1.9.4). |
| Range blob | `pkg/decisionstore/range.go`, `rangemembership.go` | `cidr=kind` + origin line; no end. Out of scope. |

There is no rate-limit leg on `master` (`grep -ril ratelimit pkg` hits only a comment in `bouncer_serve_appsec_verdict.go` and a test). The ModSecurity leg is on master (#190). It reaches the ban writer only through `banWarnCaptchaRule` / `handleRemediationServeHTTP` with `lapi.OriginPluginModsecFailure` (`pkg/bouncer/bouncer_serve_modsec.go:70,81`).

### How they connect (where the decision end lives and where it must reach)

```
stream/alone apply ──Decision{DurationSec}──▶ Store.PutMany ─┬─ memory LiveSlot{Word, ExpiresAt(+EndsAt)}  elapsed clock
live memo (memoLive) ─Decision{TTL capped, +decision end}──▶ ─┴─ Redis "kind\norigin\nscenario(\nendUnix)"  wall clock
                                                                        │
serveLAPI ──Store.LookupRemediation──▶ lookupHits (winner hit + its end) ┘  ── Range winner: no end
        └─(live/none miss) LiveLookup ──▶ queryLiveDecisions/preferLiveResult (winner duration)
        │
        ▼ kind, origin, end  →  appliedLAPIRemediation (kind only; end of the stored decision is kept)
remediateUnderActionRules ─▶ handleRemediationServeHTTP ─┬─ ban ─────────────▶ handleBanServeHTTP ─▶ handleBanStatusServeHTTP
                                                        └─ captcha ─▶ handleCaptchaKindServeHTTP ─(downgrade)─┘      │
non-LAPI callers (action-rule ban, captcha rule, failure actions, tech bans,                                          │
AppSec ban with http_status, ModSec failure) ── end = none ──────────────────────────────────────────────────────────┤
                                                                   Retry-After only if end known AND statusCode==429 ┘
```

### Every path into `handleBanStatusServeHTTP` (prod, `pkg/bouncer`)

| Caller | Origin | LAPI decision end? |
|--------|--------|--------------------|
| `handleRemediationServeHTTP` ban branch, called from `remediateUnderActionRules` in `serveLAPI` (store hit and live miss) | LAPI origin | yes |
| `handleCaptchaKindServeHTTP` downgrade (unsubscribed / unusable captcha) reached from `serveLAPI` with a LAPI captcha | LAPI origin | yes |
| `bouncer.go:189` action-rule `ban` (returns before `serveLAPI`) | `plugin:rules:<name>` | no |
| `applyCaptchaRuleServeHTTP` captcha rule served as downgrade ban | `plugin:rules:<name>` | no |
| `applyLapiFailureAction` (ban or captcha downgrade): nil client, live lookup failure, unhealthy stream | `plugin:lapi-failure` / tech stream | no |
| `serveLAPI` store error → `banWarnCaptchaRule` (`headerReasonCacheFail`) | tech cache-fail | no |
| AppSec ban `bouncer_serve_appsec_verdict.go:25` (`appsecBanStatusCode`, may be 429) | `appsec` | no |
| AppSec failure ban / captcha downgrade (`bouncer_serve_appsec.go:115,120`), AppSec empty challenge/action bans (`bouncer_serve_appsec_verdict.go:56`) | appsec | no |
| ModSec failure ban / captcha downgrade (`bouncer_serve_modsec.go:70,81`) | modsec failure | no |

HEAD: a usable captcha serves the challenge on every method, HEAD included (`handleRemediationServeHTTP` doc comment, `handleCaptchaKindServeHTTP`). That is not a ban, so it gets no header. A HEAD ban sets its headers before `WriteHeader` and skips only the body (`bouncer_serve_remediation.go:40-45`), so a HEAD LAPI ban gets the header.

### Call sites that matter (roots searched: `pkg/`, repo root `*.go`, `tests/`; `grep -rn "\.<fn>("`)

- `LookupRemediation(`: prod 1 caller (`bouncer_serve_lapi.go:34`) + forwards (`client_lookup.go`, `store.go`, `memory.go`, `redis.go`). Tests: 42 under `pkg/` + 1 in `zzz_plugin_test.go`.
- `LiveLookup(`: prod 1 (`bouncer_serve_lapi.go:65`); tests 16.
- `handleRemediationServeHTTP` prod 5 / test 5; `handleBanServeHTTP` prod 4 / test 5; `handleBanStatusServeHTTP` prod 2 / test 0; `handleCaptchaKindServeHTTP` prod 2 / test 0; `remediateUnderActionRules` prod 3 / test 0; `banWarnCaptchaRule` prod 5 / test 0.
- `LiveSlot{` literals: 1 prod (`liveslot.go:51`), 4 bench, plus size assert `zzz_pack_test.go:101` (`!= 8`).
- Redis value readers: `unpackFromString` at `redis.go:247` (slots) and `lookup.go:43` / `range.go:46` (Range blob, unchanged). No other reader of the Redis scenario: `lookupHits` returns kind and origin only.

### Reproduce

Run: a throwaway test in a `git archive` copy under the scratchpad (not in the ticket tree). Stream-mode test client, memory slot ban with `DurationSec: 3600`, `remediationStatusCode: 429`. Result: `mode=stream status=429 Retry-After="" headers=map[Cache-Control:[no-cache, no-store] Content-Type:[text/html]]`. **Reproduced.** Existing `go test ./pkg/decisionstore/ ./pkg/lapi/ ./pkg/bouncer/` pass on this machine (baseline).

### Benchmark baseline (this machine, Intel Core Ultra 7 265K, go1.25.6, `-count 3`)

| Benchmark | ns/op | B/op | allocs |
|-----------|-------|------|--------|
| CountPublishedSlots_100k | 2.29–2.32 ms | 336 | 2 |
| CountPublishedSlots_1M | 23.7–24.0 ms | 336 | 2 |
| LookupStreamMiss_100kSeq | 95.9–96.7 | 24 | 2 |
| LookupStreamMiss_100kParallel | 9.0–10.3 | 24 | 2 |
| HeapRetained_LiveMap100k | 8.44–8.71 ms | 5.10 MB | 100261 |

Throwaway scratch measure, `map[string]{uint32,int32}` vs `{uint32,int32,int32}`, map storage only (keys excluded): 100k 3.53 → 5.27 MB, 400k 13.98 → 21.01 MB, 1M 55.92 → 84.00 MB (+50 %: each map entry goes from 24 to 32 bytes after alignment). Lookup of one key: 10.9–11.3 vs 11.3–11.6 ns (no change). Cloning a 100k map (live PutMany / BeginTick): 3.4 → 4.2–4.5 ms, 3.50 → 5.25 MB. The 400k total in the `memory_pack.go` comment table (26.7 MB) becomes about 33.7 MB (+26 %).

### Outside facts

- RFC 9110 §10.2.3 (fetched 2026-11-21): `Retry-After = HTTP-date / delay-seconds`, `delay-seconds = 1*DIGIT`, "a non-negative decimal integer, representing time in seconds." Cited inline. No research folder was written: it is a one-line fact, and this run has no sub-agent for `opd-research:Delegate`.
- Upstream maxlerebourg#439 as summarised in `ticket/source.md` (not re-read).
- In-tree: live/none keep `?ip=` and LAPI expands Range (`knowledge/devdocs/core_plugin_decisionscope.md:39`).
- In-tree: before #178 (`15a4e33d^`, up to v1.9.3) the Redis reader was `splitKindOrigin`, which cuts only once (`pkg/decisionstore/pack.go:32` at that commit). v1.9.4+ readers cut three ways (`redis_pack.go`).

### Identity

This change sets no identity fact (client address, user, tenant, Host, trust hop). The client address stays `clientrequest.Request` from `ip.GetRemoteIP`.

### Spec drift seen (no new row)

Catalog `openspec/specs/core_plugin_decisionstore_store/spec.md` lines 173, 288 and 303 say the Redis slot is `KindOriginString(kind, origin)`. The code has written `kind\norigin\nscenario` since #178 (`redis.go:189`, `TestRedisPutHasNoInternId`). Propose rewrites that same requirement for the end field, so it states the real format there. Line 173 also pins `LiveSlot` at 8 bytes and the `LookupRemediation` return. Both get MODIFIED.

## Decisions

- Seam: the decision end is read where the decision is read (store hit or live pick) and travels explicitly from `serveLAPI` down to `handleBanStatusServeHTTP`. Every non-LAPI caller passes "no end". The writer adds `Retry-After` only when the end is known and `statusCode == 429`.
- Store/Client API: `LookupRemediation` and `LiveLookup` also return the winning hit's time left, computed on the engine's own clock at lookup time (memory: elapsed end − `elapsedNow()`; Redis: end Unix − now; live miss: parsed duration). Zero means unknown. Exact shape (extra return vs one result type) is for propose.
- Memory: `LiveSlot` gains a decision-end `int32` on the elapsed clock, 0 = unknown (12 bytes, human-approved). Stream sets it equal to ExpiresAt. Live sets it to now + decision duration while ExpiresAt stays the capped cache end. Negative (`f`) memo slots get 0.
- `Decision` carries the decision's time left separately from `DurationSec` (the store TTL). Stream sets both to the same value. Live sets `DurationSec = liveCacheTTL(…)` and the end from the full duration.
- Redis: 4th field = decision end, wall-clock Unix seconds, after `scenario` (empty scenario placeholder). Read as the last field. A non-numeric or non-positive value means no end.
- Rejected: setting `Retry-After` on `rw` in `serveLAPI` before dispatch. It would leak onto a captcha challenge, onto a cleared-gate or bypassCaptcha pass-through that reaches the origin, and onto AppSec/ModSec answers further down.
- Rejected: computing "latest end among all blocking decisions" (upstream #439). Decision 5 says the winner's end, and `lookupHits` / `preferLiveResult` already carry the winner.
- Rejected: a side map for live decision ends (keeps the 8-byte slot). It would add a second copy-on-write map with its own expiry next to the one owner.
- Rejected: upstream cache format `t;<unix ms>` (out of scope per `requirement.md`).
- Live contract: `openspec/specs/core_plugin_middleware_bouncer` (ADDED requirement next to "Ban page sets Cache-Control": LAPI ban answered 429 carries Retry-After). `openspec/specs/core_plugin_decisionstore_store` (MODIFIED: LiveSlot size, Redis value format, LookupRemediation return). Probably `openspec/specs/core_plugin_decisions_scopes` line 155 (Redis slot spelling). README `**BouncerRemediationStatusCode**` (line 1119) and the `ban` remediation row (line 143).
- Devdocs to update: `core_plugin_decisionstore.md` (lines 26, 48, KindOriginString, Gotchas), `core_plugin_middleware_ban-page.md` (Retry-After rule), `core_plugin_lapi_stream-apply.md` (Decision end on Put). Also the `memory_pack.go` comment table (8-byte slot, 400k figures).

## Open questions

- Q: Does a LAPI captcha decision answered as a ban (unsubscribed captcha, unusable captcha client, remap, HEAD) carry `Retry-After`?
  Rank: additive asked — passes an existing decision end to a branch that already exists; decision 7 names "unsubscribed captcha served as ban"
  Decision: assumed — yes, when the status is 429. It is still a LAPI decision with a known end, and the response is a ban. This covers `handleCaptchaKindServeHTTP` downgrade reached from `serveLAPI` (unsubscribed or unusable client). The remap has no edge to ban (`pkg/configuration/origin_based_decision_remap.go:44`). A bypassCaptcha request that keeps a stored ban the remap would turn into a captcha keeps that ban's own end. HEAD: a usable captcha serves the challenge on HEAD (not a ban, no header). A HEAD ban carries the header with no body.
  By: explore
- Q: Does a ban with no LAPI decision behind it (action rule, failure action, tech ban) get the header?
  Rank: additive asked — non-LAPI callers pass "no end"; decision 1 excludes technical / failure-action bans
  Decision: assumed — no. Correction to the conductor's "captcha→ban action rule": no action token turns a captcha into a ban (tokens in `knowledge/devdocs/core_plugin_middleware_action-rules.md`). A `ban` rule returns at `bouncer.go:187-191` before `serveLAPI`, so no header even when LAPI also holds a decision. A `captcha` rule downgraded to a ban (`applyCaptchaRuleServeHTTP`, origin `plugin:rules:<name>`) gets no header. A `captcha` rule that loses to a LAPI ban (`warnCaptchaSuperseded`) is a LAPI ban and gets the header. LAPI/AppSec/ModSec failure actions, the cache-fail ban and every AppSec ban (`http_status` 429 included) get no header.
  By: explore
- Q: What does the Redis end field look like, and do previous fork versions still read the value correctly?
  Rank: additive asked — adds a field to the stored value; decision 3
  Decision: assumed — wall-clock Unix seconds as the 4th line after `scenario`. Empty origin and scenario lines are written as placeholders, and all four lines are written whenever the decision duration is positive. The new reader cuts kind, then origin, then splits the rest at its last newline. The tail is the end only when it parses as a positive integer, so a numeric 3-line scenario is never read as an end. An end at or before now on the reading replica (clock skew) gives no header. `unpackFromString` (`redis.go:247`) is the only slot reader. The Range blob readers (`lookup.go:43`, `range.go:46`) pass or ignore the end. v1.9.4–v1.9.7 readers fold the line into `scenario`, which their lookup never returns (re-checked at those tags in propose). v1.9.3 and older read the origin with the rest appended, as they have for every 3-line value since v1.9.4. Kind stays correct. Not a red flag: compatible addition (design.md Migration Plan). Replica clock skew is accepted and documented.
  By: propose
- Q: Several hits (IP, header scopes, Range; live IP plus header queries): whose end?
  Rank: additive asked — the winner's hit carries its own end through the existing merge; decision 5
  Decision: assumed — the end of the hit `lookupHits` / `mergeLookupHit` chose (ban over captcha, first hit on a tie). A Range winner has no end, so no header, even when the IP slot holds a captcha with an end. Live: `preferLiveResult` keeps the winner's duration. `strongestLiveDecision` picks the first ban LAPI lists, not the longest, so its end can be shorter than another ban's. Decision 5 accepts that: a short value only makes the client come back early.
  By: explore
- Q: Memory slot layout and clock for the decision end?
  Rank: additive asked — adds a field to `LiveSlot`; decision 2 approves 12 bytes
  Decision: assumed — `LiveSlot{Word uint32, ExpiresAt int32, <decision end> int32}` on the elapsed clock (0 = unknown; `elapsedBias` keeps a known end ≥ 2). It is turned into seconds left at lookup. Stream: end = ExpiresAt. Live: end from the full decision duration, ExpiresAt the capped cache end. Measured cost: map storage +50 % (400k: 14.0 → 21.0 MB; total with keys about 26.7 → 33.7 MB), 100k clone 3.4 → 4.2–4.5 ms, no change to key lookup. `zzz_pack_test.go:101` size assert becomes 12.
  By: explore
- Q: Do Range-scope bans get the header in live/none, where LAPI expands Range on `?ip=` and returns the decision's duration?
  Rank: additive incidental — no existing structure changes, and keeping the header is the default of the live path; decision 4 names only "Range-scope bans" with the blob as the reason
  Decision: assumed — yes in live/none, no in stream/alone. Decision 4's reason (the Range-index blob has no end) only holds for stream/alone. In live/none the end is known, and decision 1's conditions are met. Dropping it would add a scope check to `queryLiveDecisions` only to hide a known end. The README states the Range exception for stream/alone. Recorded in `deviations.md`.
  By: explore
- Q: What does a value without an end (written by an older instance, or a live memo before upgrade) produce?
  Rank: additive asked — reader treats a missing field as "no end"; decision 3 / requirement Unknowns
  Decision: assumed — no header. The README documents it as a rolling-upgrade gap that closes when the key expires.
  By: explore
- Q: How does the end reach the writer without leaking to non-LAPI bans?
  Rank: bounded asked — changes existing internal bouncer functions with enumerated callers (`handleRemediationServeHTTP` 5 prod/5 test, `handleBanServeHTTP` 4/5, `handleBanStatusServeHTTP` 2/0, `handleCaptchaKindServeHTTP` 2/0, `remediateUnderActionRules` 3/0; root `pkg/`); requirement Desired "Correct under `bouncerActionRules` … unsubscribed captcha served as ban" and decision 1
  Decision: assumed — one `decisionLeft time.Duration` parameter on `remediateUnderActionRules`, `handleRemediationServeHTTP`, `handleCaptchaKindServeHTTP`, `handleBanServeHTTP`, and `handleBanStatusServeHTTP`, set only in `serveLAPI` from the two lookups. Every other caller passes the named zero `noLAPIDecisionEnd`. `banWarnCaptchaRule` keeps its signature and passes it itself (no LAPI decision is behind any of its callers). A value type was rejected: below `handleRemediationServeHTTP` the writer takes reason, header reason, origin, and status, not kind, so kind+origin+end do not travel as one cluster (design.md Decision 1).
  By: propose
- Q: How do the Store and Client lookups return the end?
  Rank: bounded asked — grows existing returns; callers enumerated: `LookupRemediation` 1 prod + 4 forwards, 43 tests (42 `pkg/`, 1 root `zzz_plugin_test.go`); `LiveLookup` 1 prod, 16 tests; requirement Desired "stream/alone: end from the stored decision (memory slot or Redis value)" and "live/none miss: end of the decision that produced the ban"
  Decision: assumed — an extra `decisionLeft time.Duration` return before `err`: `Store.LookupRemediation` / engine `lookup` / both engines / `Client.LookupRemediation` return `(kind, origin, originID, decisionLeft, err)`, and `LiveLookup` returns `(kind, origin, decisionLeft, err)`. Zero = unknown. A result struct was rejected (single production caller destructures at once; tuple style kept). Catalog lines MODIFIED in `core_plugin_decisionstore_store`, `core_plugin_decisions_scopes`, `core_plugin_middleware_bouncer`.
  By: propose
- Q: Rounding and value of the header?
  Rank: additive asked — formats a new header in the existing writer; requirement Desired line 1 (rounded up, at least 1)
  Decision: assumed — `Retry-After` = max(1, ceil(seconds left)) as delay-seconds (RFC 9110 §10.2.3), set before `WriteHeader` next to `Cache-Control`. Only when an end is known and `statusCode == 429`. No header on 403, on other codes, or when the end is unknown.
  By: explore
- Q: What e2e coverage can be added without disturbing other routers?
  Rank: additive asked — new routers and assertions in existing suites; decision 6
  Decision: assumed — Mock: 429 router in `stream-mode` and `live-mode` (`Retry-After` in `1..300` for a `5m` ban, none on the 403 router); `redis`: 4-line canned value with a per-request end for a new IP, and bare `t` for `1.2.3.5` proves no header without an end; range and absent-header helpers in `lib/common.sh`. Real: extend `/status-429` in `simple-bouncer.Tests.ps1` (none mode, `1..3600`) plus a no-header check on a 403 route; stream on a new file-provider router `config/dynamic/retry-after.yml` with its own key `BOUNCER_KEY_RETRY_AFTER_STREAM`, asserted in `mode_stream.Tests.ps1` (the instance-severance T5 subscriber is torn down on purpose by its suite, so it was not reused); the existing AppSec `RateLimit()` 429 test asserts no `Retry-After`. Implement built it as planned; the live-mode 429 router asserts `3..300` (past the 2s cache TTL). A Redis 4-line value at 429 is proven at store level (`pkg/decisionstore/zzz_decision_end_test.go`) and in mock `redis`, not in a `pkg/bouncer` unit test: the in-process RESP stand-in is private to `pkg/decisionstore` tests, and the bouncer path is engine-agnostic (`Store.LookupRemediation`). Local runs: mock `stream-mode`, `live-mode`, `redis` passed (Linux container); Pester `simple-bouncer`, `mode_stream`, `appsec` passed (30/30).
  By: implement
