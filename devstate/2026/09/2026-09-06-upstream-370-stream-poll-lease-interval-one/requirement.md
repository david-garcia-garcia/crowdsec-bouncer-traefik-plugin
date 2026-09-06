# Requirement
IssueKey: 2026-09-06-upstream-370-stream-poll-lease-interval-one

## Problem

Upstream #370: with `updateIntervalSeconds: 1`, the stream poll lease key (`updated`) is never stored because lease TTL is `updateInterval - 1` (= 0). Zero TTL is a no-op in the local cache and fails on Redis, so multi-instance deployments poll LAPI on every tick instead of one poll per interval. Our fork already floors lease duration at 1 second, but no test proves the fix for interval 1.

## Current (code)

- `pkg/lapi/client_stream.go:77-81` — `handleStreamCache` sets `leaseDuration := c.updateInterval - 1` and floors to 1 when `< 1`, then `Set(cacheTimeoutKey, …, leaseDuration)`.
- `pkg/lapi/client_stream.go:67-72` — lease hit on `cacheTimeoutKey` skips LAPI fetch and hydrates range membership.
- `pkg/configuration/configuration.go:502-511` — `UpdateIntervalSeconds` validated `>= 1` via `requiredInt1`.
- `pkg/lapi/client_range_test.go:54-64` — `TestHandleStreamCacheLeaseHitHydrates` pre-seeds lease with TTL 60; no case for `updateInterval == 1`.
- `pkg/cache/cache.go:233` — `Client.Set` delegates to local or Redis backend with the given duration.

## Desired

Add unit test(s) in `pkg/lapi` that with `updateIntervalSeconds: 1`, after a stream cache miss path stores `cacheTimeoutKey`, a subsequent lease hit suppresses LAPI fetch (same guard behavior as existing lease-hit test). Do not change product behavior unless a test cannot be honest without a one-line correctness fix.

## Affected

- `pkg/lapi/client_range_test.go` (or new test file in `pkg/lapi`) — lease store assertion for interval 1.
- `pkg/lapi/client_stream.go` — read-only unless test honesty requires a minimal fix.

## Out of scope

- Reverting or changing the existing lease floor logic (already matches upstream suggested fix).
- Redis `SET EX 0` error surfacing / caller distinguish stored vs not stored (upstream note).
- Multi-instance integration or e2e with shared Redis.
- Other stream poll concurrency or health semantics.
- Configuration validation changes.

## Unknowns

- Whether tests should cover Redis backend explicitly or in-memory cache alone is sufficient to prove lease storage at interval 1.

## Tensions

- Assessment says `affected: no` (fix already in tree) but upstream impact is real for multi-node Redis; this run is proof-only via tests, not a behavior change PR.
- Ticket describes upstream `bouncer.go` path; lease logic lives in `pkg/lapi/client_stream.go` on this fork — behavior is equivalent but path differs from issue links.
