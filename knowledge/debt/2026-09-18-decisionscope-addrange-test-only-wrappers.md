# `AddRange` / `RemoveRange` are test-only wrappers that swallow an error

IssueKey: 2026-09-18-ip-cache-key-canonicalization
Size: large
Action: note

## Why this follow-up

`decisionscope.AddRange` and `decisionscope.RemoveRange` have no production caller. The stream path
builds its upserts and removals and calls `ApplyRangeBatch` directly; the only callers of these two
are tests in `pkg/decisionscope` and `pkg/lapi`. Now that `ApplyRangeBatch` reports a failed read,
both wrappers discard that error with `_ =`, so a test helper can quietly succeed on a cache that
never answered — which is exactly the failure mode the change they wrap exists to stop.

## Why it was not taken

Deleting them means rewriting roughly a dozen call sites across two packages' test files in a change
whose diff is otherwise five product files. Mixing that in would bury the two defects this PR is
meant to be reviewed for, and the wrappers are not part of either one.

## Risks

A later test written against `AddRange` reads as proof that a Range decision landed when it may not
have. The risk is confined to tests; no production path can reach it today, and if one is added the
compiler will not warn that the error is being dropped.

## Context

Current: `pkg/decisionscope/range.go` `AddRange`, `RemoveRange`
Proposed: delete both; tests call `ApplyRangeBatch` and assert its error
Call sites: `pkg/decisionscope/zzz_range_test.go`, `pkg/lapi/zzz_client_range_test.go`
