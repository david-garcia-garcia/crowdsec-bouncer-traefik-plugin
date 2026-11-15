## 1. Challenge prefix keeps AppSec

- [x] 1.1 `pkg/bouncer/bouncer.go`: `foldActionRules` clears `SkipAppsec` when `isCrowdsecChallengeCallbackPath`; `ServeHTTP` and the test helper `continueAfterLAPIForTest` call it.
- [x] 1.2 Flip subtest "appsec bypass rule custom.js" to expect 404 and no `next`; add `TestFoldActionRulesChallengePathKeepsAppsec`.

## 2. Single-reading path for skip rows

- [x] 2.1 `pkg/httprule/path.go` `SingleReadingPath`; `Fold` drops skips of path rows on an ambiguous path and sets `AmbiguousPathName`.
- [x] 2.2 `TestSingleReadingPath`, `TestActionSet_foldAmbiguousPathDropsPathSkipsOnly`, `TestServeAppSecAmbiguousPathStillQueriesAppsec`.
- [x] 2.3 Mock e2e `request-bypass-rules`: `/skipzone/403` skipped (200); `/skipzone/..;/403`, `/skipzone/%2E%2E;/403`, `/skipzone/..%5C403` reach AppSec (403).

## 3. Docs

- [x] 3.1 README `BouncerActionRules`; devdocs `core_plugin_httprule.md`, `core_plugin_middleware_action-rules.md`, `core_plugin_appsec.md`; explore.md reversal note.

## 4. Verify

- [x] 4.1 `go test ./pkg/httprule/ ./pkg/bouncer/`; mutation check (fix disabled → the new tests and the e2e assertion fail).
