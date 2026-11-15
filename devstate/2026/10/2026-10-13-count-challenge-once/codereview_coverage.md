# Test coverage

1. [hard] Edge case untested — `pkg/bouncer/bouncer.go:312` — the new 404 guard special-cases `!match.SkipAppsec && b.subscribeAppSec` (design decision 4: SkipAppsec still calls `next`), and no test drives a challenge-prefix path through either arm
   Fix: Add one test with a SkipAppsec action match and one with AppSec not subscribed on `/crowdsec-internal/challenge/custom.js`, asserting `next` is called and the status is not 404
   Status: done
   Argument: Added subtests `appsec bypass rule custom.js` and `appsec not subscribed custom.js` to `TestHandleNextServeHTTPAllowKeepsChallengePathsFromOrigin`: both reach `next` with no 404.
