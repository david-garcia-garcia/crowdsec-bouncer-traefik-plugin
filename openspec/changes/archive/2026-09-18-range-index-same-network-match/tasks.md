## 1. Same-network compare

- [x] 1.1 Add unexported `indexCIDRsSameNetwork(existing, cidr string) bool` in `pkg/decisionscope/range.go` next to the two loops: `net.ParseCIDR` both sides, then `*net.IPNet.IP.Equal` plus matching `Mask.Size()` ones and bits; if either parse fails, return raw-text `==`
- [x] 1.2 In `upsertIndexCIDR` and `removeCIDRFromIndex`, replace the string `==` CIDR check with that helper. Persist the incoming CIDR text on replace/append. Do not change `ApplyRangeBatch` order or read-error contract

## 2. Tests

- [x] 2.1 In `pkg/decisionscope/zzz_range_test.go`, add `AddRange(10.1.2.0/8)` then `RemoveRange(10.0.0.0/8)` and assert membership for `10.1.2.3` is clear
- [x] 2.2 Next to that case, add one unparseable identical-text remove that drops the line

## 3. Verify

- [x] 3.1 `go test ./pkg/decisionscope/ ./pkg/lapi/ -count=1` including `TestApplyRangeBatch_UnreachableReadKeepsSharedIndex` and `TestApplyRangeBatch_UnreachableReadDoesNotDeleteIndex`
