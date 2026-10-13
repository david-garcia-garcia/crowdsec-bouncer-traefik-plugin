# Windows range-index read classifies as unsupported-reply

IssueKey: 2026-09-24-lapi-open
Size: large
Action: note

## Why this follow-up
`TestApplyRangeBatch_UnreachableReadKeepsSharedIndex` on this Windows machine gets `redis:unsupported-reply` from a dead `127.0.0.1:1` replica instead of `decisionstore.ErrUnreachable`. The shared index is still kept.

## Why it was not taken
Dest already fails the same test without this change. The ticket is one `lapi.Open`. Error classification lives in DecisionStore / SimpleRedis, not the Open surface.

## Risks
Linux CI may stay green while Windows `go test ./...` keeps failing on this one case. A later ticket that wraps reader failures as `ErrUnreachable` should own it.

## Context
`pkg/lapi/zzz_ipcachekey_test.go` `TestApplyRangeBatch_UnreachableReadKeepsSharedIndex`. Sibling `TestApplyRangeBatch_UnreachableReadDoesNotDeleteIndex` only checks non-nil error and passes.
