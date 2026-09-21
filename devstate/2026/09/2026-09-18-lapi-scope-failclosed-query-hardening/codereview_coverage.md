# Test coverage

1. [judgement] Happy path only — `pkg/lapi/client_stream.go:92` — the lease release is proven on the in-memory store only. The spec sentence "Release SHALL behave the same on the Redis and the in-memory store" is carried by `cache.Client.Delete` (`pkg/cache/cache.go:214`) dispatching to `localCache.delete` or `redisCache.delete`; the three new tests all run `newTestStreamPoller`, which is memory-backed.
   → Assert the release on a Redis-backed store in the suite that already has a Redis fixture, if one exists for `pkg/lapi`
   Status: skipped
   Argument: judgement. `pkg/lapi` unit tests have no Redis fixture and the gates the ticket names do not start one, so adding this would mean standing up a new dependency for one delete. The delete is a single store-agnostic call on a `Delete` that `pkg/cache/zzz_cache_test.go:92` already covers, and this diff did not touch either store implementation.

Ticket job (from `devstate/requirement.md` and the primary SHALL in `core_plugin_lapi_failure-action`): a header-scope LAPI query that errors must stop being read as "no decision" and must reach `bouncerLapiFailureAction` with a non-active remediation, without ever masking an active ban.

That job would fail on revert. Six tests, one per matrix row, in `pkg/lapi/zzz_failure_action_test.go`, each measured red on dest `0e7dbf0` first:

- Row 1 clean IP + clean scopes allows — `TestLiveLookup_CleanIPAndCleanScopesAllows:114`.
- Row 2 clean IP + scope error fails closed — `TestLiveLookup_ScopeErrorFailsClosed:130`; asserts non-nil error, non-active kind, and that the client address was not negatively cached, so it fails if any of the three hunks is reverted.
- Row 3 clean IP + scope ban — `TestLiveLookup_ScopeBanWins:145`.
- Row 4 active ban + scope error — `TestLiveLookup_ActiveBanOutranksScopeError:160`; asserts the error is still `handleNoStreamCache:banned`, which is what proves the ban is not downgraded or replaced by the scope error.
- Row 5 IP-query error unchanged — `TestLiveLookup_IPErrorStillPropagates:175`.
- Row 6 one scope errors, another bans — `TestLiveLookup_ScopeBanWinsOverAnotherScopeError:189`.

The log-level SHALL has its own test: `TestLiveLookup_ScopeErrorLogsAtWarn:208` runs the same failure at `INFO` and at `ERROR` and asserts the line is present at `INFO`, which is the plugin default, and absent at `ERROR`. A revert to `Debug` fails the `INFO` case.

Critical paths this change owns, each with an outcome assertion:

- Lease release on a failed poll — `TestHandleStreamCache_FailedGetReleasesLease:97` (GET 500) and `TestHandleStreamCache_UndecodableBodyReleasesLease:131` (decode failure), both asserting `cacheTimeoutKey` is absent. Success keeping the lease is asserted in `TestHandleStreamCache_NextTickRepollsAfterFailure:111` at `:124`, and the same test proves the retry actually re-polls by counting stream hits.
- 401 replay — `TestCrowdsecQuery_TokenRenewalReplaysPostBody` asserts the reissued request is a POST with the same body, so the `nil` body of `0e7dbf0` fails it.
- Unbounded recursion — `TestCrowdsecQuery_SecondUnauthorizedStopsRetrying` and `TestGetToken_UnauthorizedLoginDoesNotRecurse`; on dest the first one exhausted the stack and panicked, which is the measurement that the `mayRenewToken` gate is the fix.
- Drain and reuse — `TestCrowdsecQuery_ReusesConnection:164` runs ten calls per status over `200`, `500`, `502`, `503`, `504` and requires one connection, which covers both the reverse-proxy branch and the plain non-2xx branch the spec names.
- Message accuracy — `TestCrowdsecQuery_ReverseProxyStatusMessageNamesTheStatus` asserts the URL and `503` are present and `%!w(<nil>)` is absent; `TestCrowdsecQuery_TransportErrorWrapsItsCause` asserts `errors.Is` still reaches the transport cause.

No new production branch in the diff is unexercised: `identifier == ""` in `mergeLiveScope` is covered by the existing nil-scopes tests (`Test_liveLookup_lapiErrorIsNotABan:73`, `TestLiveLookup_PerRouterTTLLastWrites:88`), and the `current == nil` transport guard predates the diff.