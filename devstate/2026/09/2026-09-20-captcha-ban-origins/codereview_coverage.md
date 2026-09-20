# Test coverage

**Ticket job (source: `devstate/.../requirement.md`, proposal Why):** For configured `CaptchaBanOrigins`, store captcha kind `c` instead of ban `t` when LAPI type is `ban` and `MetricsOrigin(origin, scenario)` matches, on stream and live apply paths (including per-list `lists:<name>` and bare `lists`).

**Tests in diff / still relevant:** `pkg/lapi/zzz_captcha_ban_origins_test.go` (match rules, copy trim, `remediationKindForOrigin`, `streamPutItem`, `strongestLiveDecision`); `tests/e2e/mock/scenarios/captcha-ban-origins/run.sh` (stream mode: listed CAPI / `lists:firehol_level1` → captcha page, tor-exit / cscli → 403).

1. [hard] Critical path untested — `pkg/lapi/client_stream.go:166-168` — `kind := c.remediationKindForOrigin(decision.Type, origin)` on stream Range upsert; reverting to `RemediationValue(decision.Type)` leaves all tests green
   → Assert a Range stream decision with a listed origin stores captcha in the range upsert payload (same as Ip `streamPutItem` job)
   Status: done
   Argument: TestHandleStreamCacheRangeCaptchaBanOrigins asserts LookupRemediation captcha after a listed Range stream upsert.

2. [hard] Critical path untested — `pkg/lapi/client_decisions.go:115-116` — `queryLiveDecisions` sets cached `liveResult.kind` via `c.remediationKindForOrigin(picked.Type, origin)`; `TestStrongestLiveDecisionCaptchaBanOrigins` only exercises `strongestLiveDecision` plus a separate `remediationKindForOrigin` call, not `queryLiveDecisions` — reverting the kind line to `RemediationValue(picked.Type)` stays green for listed-only live picks
   → Assert `queryLiveDecisions` (or live lookup using it) returns kind `c` when the picked decision is a listed-only `ban`
   Status: done
   Argument: TestLiveLookupCaptchaBanOrigins asserts LiveLookup kind captcha for a listed-only CAPI ban.

3. [judgement] Happy path only — `pkg/lapi/client.go:134` — first-create copy of `CaptchaBanOrigins` is exercised only via e2e wiring, not a unit test that a second reclaimed `New` keeps the first list (spec scenario)
   → Add a reclaim test asserting the first Client list wins, or skip if e2e + copy helper tests are enough for this change
   Status: skipped
   Argument: judgement; copyCaptchaBanOrigins is unit-tested and first-create residue matches updateMaxFailure — not a second Open-key test this change.
