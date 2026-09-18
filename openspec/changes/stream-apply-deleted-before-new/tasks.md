## 1. Apply order

- [ ] 1.1 In `fetchAndApplyStreamDecisions`, loop `stream.Deleted` (IP/header delete, Range removals, forget) before `stream.New` (IP/header store, Range upserts, remember)
- [ ] 1.2 In `ApplyRangeBatch`, apply removals before upserts; keep one cache read and one write

## 2. Regression tests

- [ ] 2.1 `TestHunt_StreamAppliesDeletedBeforeNew`: one payload new+deleted for the same IP; dest order fails, swapped order leaves the ban
- [ ] 2.2 `TestHunt_StreamRangeAppliesDeletedBeforeNew`: one payload new+deleted for the same CIDR; dest order fails, swapped order leaves Range membership banned

## 3. Verify

- [ ] 3.1 `go test ./pkg/lapi/ ./pkg/decisionscope/ -count=1` and the two hunt names fail before the swap if run against dest order, pass after
- [ ] 3.2 Existing stream lease / overlap tests stay green
