## 1. Canonicalize at origin

- [ ] 1.1 After a successful parse in `ServeHTTP`, set `req.remoteIP = req.ipAddr.String()`. Keep the raw string on extract-fail and nil-`ipAddr` (`tech_trustipfail`) paths.
- [ ] 1.2 Do not add a fourth address field. Do not change `GetRemoteIP`'s `(raw, parsed)` return.

## 2. Drop the request-path helper

- [ ] 2.1 Delete `IPLookupCacheKey`. Key `LookupCachedRemediation` / `LookupCacheKeys` on `remoteIP`. Keep `ipAddr` only for Range membership.
- [ ] 2.2 Live memo writes `Set(remoteIP, …)` and does not call `IPCacheKey` on the request path. Store/delete still use `IPCacheKey`.
- [ ] 2.3 Rewrite units that name `IPLookupCacheKey` so they assert the canonical `remoteIP` key. Keep `TestLiveLookup_MemoHitsOnRepeatedRequests`.

## 3. Usage and real e2e

- [ ] 3.1 Fold `knowledge/devdocs/core_plugin_decisionscope.md` Language `Ip cache key` so the request-side key is `clientRequest.remoteIP` after parse.
- [ ] 3.2 Add none- and stream-mode Ip-spelling cases to `tests/e2e/real/decision_scopes.Tests.ps1`: insert expanded IPv6, upper-case IPv6, and IPv4-mapped via `Add-TestDecision` (or `Add-TestScopeDecision` if cscli rejects mapped); request a different spelling through `Test-HttpRequest` XFF; assert ban.

## 4. Verify

- [ ] 4.1 Run the package tests that cover decisionscope, lapi live memo, captcha bind, and bouncer parse-fail logs.
- [ ] 4.2 Run the new real-stack cases when the Docker harness is up (`make e2e_pester` or the single file). If the harness is not up locally, say so and rely on CI `e2e (docker + pester)`.
