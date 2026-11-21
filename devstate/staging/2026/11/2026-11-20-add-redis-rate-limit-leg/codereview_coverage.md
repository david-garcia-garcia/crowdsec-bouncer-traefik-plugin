# Test coverage

1. [hard] Edge case untested — `pkg/ratelimit/key.go:69` — an empty capture group (pattern matches, group 1 is "") is special-cased as a missing value (spec: "an empty value … SHALL skip the bucket"), but no key or charge test hits it; the only pattern-miss case (`pkg/ratelimit/zzz_key_test.go:55`) takes the `len(groups) < 2` arm
   Quote:
   ```
   if len(groups) < 2 || groups[1] == "" {   // key.go:69
   {From: KeyFromPath, Pattern: "^/u/([^/]+)/"},   // zzz_key_test.go:55, no match, never an empty group
   ```
   Fix: Add a key case such as `{From: path, Pattern: "^/t/([^/]*)/"}` on `/t//x` and assert the part reports missing (bucket not charged)
   Status: done
   Argument: `TestCounterKey_eachSource` adds `^/t/([^/]*)/` on `/t//orders` and asserts the part is missing; mutation-checked (fails without the empty-group arm).
2. [judgement] Edge case untested — `pkg/ratelimit/charge.go:57` — spec says an error returned with a local verdict is decided by the failure action and the local verdict is ignored; both fake counters return `allowed=true` with the error (`pkg/bouncer/zzz_rate_limit_test.go:47`, `pkg/ratelimit/zzz_charge_test.go:33`), so a Charge that honoured a local deny before the error would stay green
   Fix: Make one fake return `false, n, err` and assert passthrough reaches the backend (and ban answers `ban:ratelimit-failure`, not `ban:ratelimit:<bucket>`)
   Status: skipped
   Argument: judgement: `Charge` returns on `err` before reading `allowed` (`charge.go:57`); a fake returning a local deny with the error is a guard test, not a missing outcome.
3. [judgement] Happy path only — `pkg/bouncer/bouncer_serve_ratelimit.go:70` — failure action `captcha` returns `handleCaptchaKindServeHTTP`'s result so a valid gate cookie continues to AppSec (spec: "A valid gate cookie lets the request continue"); `TestRateLimit_failureActions` covers challenge, bypassCaptcha, and downgrade, not the cleared-gate arm
   Fix: Add a failure-captcha case with a gate cookie that `Check` accepts and assert `next` is called with no remediation header and no drop
   Status: skipped
   Argument: judgement: the cleared-gate arm is the shared `handleCaptchaKindServeHTTP` return, not code this leg adds; a rate-limit case for it is an extra guard, left for a later pass.
4. [judgement] Happy path only — `pkg/ratelimit/client.go:85` — the `Sleep`/`Wake` reclaim hooks (flush buffered hits when the last holder leaves, restart the flush timer on rebind within grace) are never asserted; every test runs `reclaim.ResetForTestWith(0)` and checks only share, new-on-change, and Close
   Fix: With a non-zero grace, cancel the holder ctx, Open again, and assert the same Client is returned and still counts (or drop it if the realredis buffered test is meant to own it)
   Status: skipped
   Argument: judgement: Sleep/Wake delegate to the vendored limiter in one line each; a non-zero-grace reclaim test is an extra guard, left for a later pass.
5. [judgement] Weak assertion — `pkg/ratelimit/key.go:111` — parts are joined with NUL so `("a","bc")` and `("ab","c")` hash apart (design 7, spec "joined with a NUL byte"); every key test uses one part or a missing part, so changing the separator to "" stays green
   Fix: Add a two-part key case asserting `("a","bc")` and `("ab","c")` give different Redis keys
   Status: skipped
   Argument: judgement: a guard on an internal format choice (design 7), not a ticket outcome; left for a later pass.
