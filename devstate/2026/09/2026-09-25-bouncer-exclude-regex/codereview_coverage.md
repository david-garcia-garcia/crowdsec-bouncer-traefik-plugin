# Test coverage

1. [hard] Critical path untested — `pkg/bouncer/bouncer.go:369` — compiled exclude that does not match this request; ServeHTTP tests only hit empty or match so skip-when-non-nil stays green
   Quote:
      ```
      return compiled != nil && compiled.MatchString(excludeMatchString(httpReq))
      TestServeHTTP_emptyLapiExcludeStillLooksUp (empty/nil only); TestServeHTTP_lapiExcludeSkipsStreamStoreAndUnhealthy and TestServeHTTP_appsecExcludeSkipsQuery (match only); TestServeHTTP_trustedIPStillSkipsPlugin sets ^nomatch$ but trusted IP returns first; (none) for compiled miss
      ```
   Fix: Assert a compiled LAPI exclude that does not match still applies the store ban, and a compiled AppSec exclude that does not match still Queries
   Status: done
   Argument: Added `TestServeHTTP_nonMatchingLapiExcludeStillLooksUp` and `TestServeHTTP_nonMatchingAppsecExcludeStillQueries`.
