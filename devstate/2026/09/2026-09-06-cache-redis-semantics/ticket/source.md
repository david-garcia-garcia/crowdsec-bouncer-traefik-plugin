# Memory vs Redis TTL-zero split, swallowed mutation errors, and reads that skip the writer

## Problem

`pkg/cache` Redis vs in-memory semantics diverge on paths that hide failed or stale remediations:

1. Duration 0: memory skips Set; Redis sends `EX 0`.
2. Redis Set/Delete failures are logged only; callers cannot detect failed writes (decisions, leases, captcha grace).
3. Gets round-robin `readHosts` and never use the writer after Set; replica lag looks like a miss.
4. CRUD tests only hit `localCache`.

Captcha ticket `2026-09-06-captcha-handler-hardening` also wants observable Set for grace period. Change `Set`/`Delete` in this ticket as the owner of the cache API; captcha can consume the new return value. If that PR already landed a return value, extend it — do not invent a second API.

## Evidence

Sibling files: `ttl-zero-memory-redis-split.md`, `redis-mutation-errors-swallowed.md`, `redis-get-bypasses-writer.md`, `missing-redis-crud-parity-tests.md`.

## Current behavior

TTL 0 and write errors behave differently per backend. Reads can miss a just-written key on replicas. No Redis CRUD parity tests.

## Desired

Same TTL-0 contract on memory and Redis (document it). Return errors from Set/Delete (or equivalent) so callers can fail closed. After a write, read from the writer (or otherwise not serve a stale replica miss as empty). Redis CRUD parity tests.

## Grouped with this file

- ttl-zero-memory-redis-split
- redis-mutation-errors-swallowed
- redis-get-bypasses-writer
- missing-redis-crud-parity-tests

## Out of scope

Remediation encoding (tested). localCache mutex. Key prefix design.
