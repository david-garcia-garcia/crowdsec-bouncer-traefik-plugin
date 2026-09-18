# Test coverage

1. [hard] Edge case untested — `pkg/decisionscope/range.go:171` — unparseable incoming remove returns the blob unchanged; no test would fail if that miss deleted by string
   → Assert `RemoveRange("not-a-cidr")` leaves an existing Range ban in place
   Status: done
   Argument: added `TestRemoveRangeUnparseableCIDRSkipped` in `pkg/decisionscope/zzz_range_test.go` (0426ec4).
2. [judgement] Happy path only — `pkg/decisionscope/range.go:180` — leftover unparseable blob lines stay via `!existingOK`; no dedicated assert
   → Assert a leftover `not-a-cidr=t` line survives an unrelated upsert
   Status: skipped
   Argument: judgement; leftover unparseable uses the same keep-other-lines path already asserted by `TestApplyRangeBatchUnrelatedLeftoverSpellingStays`.
