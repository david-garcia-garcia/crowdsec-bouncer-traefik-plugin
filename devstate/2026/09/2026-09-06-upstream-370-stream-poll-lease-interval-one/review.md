## prepare (2026-09-06)
phase: prepare
findings: qualified, add-tests scope for upstream #370 lease at interval 1
fixed: requirement grounded, stub PR #47
skipped: none

## explore (2026-09-06)
phase: explore
findings: floor already in handleStreamCache; no interval-1 store test; in-memory miss→store is enough
fixed: explore.md with Decisions and four assumed open questions
skipped: Redis EX 0 test; TTL-expiry sleep; product code change

## propose (2026-09-06)
phase: propose
findings: new spec core_plugin_lapi_stream-lease; tests not applied
fixed: OpenSpec change stream-poll-lease-interval-one apply-ready
skipped: product code
