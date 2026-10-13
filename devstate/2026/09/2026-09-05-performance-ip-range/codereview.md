# Code review
Pin: origin/master (cefbf9d) `git diff origin/master...HEAD -- . ':!devstate' ':!.cursor'`

## Standards
1. [hard] Fix the cause — `pkg/decisionscope/lookup.go:60` — `LookupCacheKeys(..., false)` hardcodes the request path off `range-index` while the helper still exposes `useRangeIndex`
   → Remove `useRangeIndex` from `LookupCacheKeys`
2. [judgement] Duplicated Code — `MembershipFromIndex` vs `MatchRangeFromIndex` share blob-line iteration
   → Extract shared iteration (not applied)

## Spec
none

## Security
none

## Performance
none

## Applied
- Standards 1: dropped `useRangeIndex` from `LookupCacheKeys`; request-path GetMany cannot include `RangeIndexKey`

## Recorded and skipped
- Standards 2: judgement duplicated blob-line loop; MatchRangeFromIndex still owns blob walk tests; extract would be extra abstraction this change did not need

Standards: 2 findings, worst: Fix the cause at `pkg/decisionscope/lookup.go:60`
Spec: 0 findings, worst: none
Security: 0 findings, worst: none
Performance: 0 findings, worst: none
