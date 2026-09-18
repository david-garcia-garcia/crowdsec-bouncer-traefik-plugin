# Test coverage

1. [hard] Edge case untested — `pkg/decisionscope/range.go:74` — parse-fail fallback `return existing == cidr` keeps a parseable line only when the unparseable text differs; spec scenario "Parseable and unparseable text are not the same line" has no test that would fail if that miss returned true
   → Assert `AddRange(10.0.0.0/8)` then `RemoveRange("not-a-cidr")` still bans `10.1.2.3`
   Status: done
   Argument: added TestRemoveRangeParseableVsUnparseableKeepsLine in pkg/decisionscope/zzz_range_test.go (bb343d7)
2. [hard] Edge case untested — `pkg/decisionscope/range.go:91` — same-network upsert now takes the replace path and persists incoming text; spec scenario "Same-network upsert persists the incoming spelling" has no blob assertion that would fail if the helper were reverted or persist became `(*net.IPNet).String()`
   → Assert `AddRange(10.1.2.0/8)` captcha then `AddRange(10.0.0.0/8)` ban leaves `10.0.0.0/8` plus the new remediation
   Status: done
   Argument: added TestAddRangeSameNetworkPersistsIncomingSpelling in pkg/decisionscope/zzz_range_test.go (bb343d7)
