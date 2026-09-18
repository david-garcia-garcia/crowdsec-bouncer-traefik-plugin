## 1. Canonicalize at origin

- [x] 1.1 After a successful parse in `ServeHTTP`, set `req.remoteIP = req.ipAddr.String()`. Keep the raw string on extract-fail and nil-`ipAddr` (`tech_trustipfail`) paths.
- [x] 1.2 Do not add a fourth address field. Do not change `GetRemoteIP`'s `(raw, parsed)` return.

## 2. Drop the request-path helper

- [x] 2.1 Delete `IPLookupCacheKey`. Key `LookupCachedRemediation` / `LookupCacheKeys` on `remoteIP`. Keep `ipAddr` only for Range membership.
- [x] 2.2 Live memo writes `Set(remoteIP, …)` and does not call `IPCacheKey` on the request path. Store/delete still use `IPCacheKey`.
- [x] 2.3 Rewrite units that name `IPLookupCacheKey` so they assert the canonical `remoteIP` key. Keep `TestLiveLookup_MemoHitsOnRepeatedRequests`.

## 3. Usage and real e2e

- [x] 3.1 Fold `knowledge/devdocs/core_plugin_decisionscope.md` Language `Ip cache key` so the request-side key is `clientRequest.remoteIP` after parse.
- [x] 3.2 Add none- and stream-mode Ip-spelling cases to `tests/e2e/real/decision_scopes.Tests.ps1`: insert expanded IPv6, upper-case IPv6, and IPv4-mapped via `Add-TestDecision` (or `Add-TestScopeDecision` if cscli rejects mapped); request a different spelling through `Test-HttpRequest` XFF; assert ban.

## 4. Verify

- [x] 4.1 Run the package tests that cover decisionscope, lapi live memo, captcha bind, and bouncer parse-fail logs.
- [x] 4.2 Real-stack not run locally (no `crowdsec-test` container). Rely on CI `e2e (docker + pester)`.
