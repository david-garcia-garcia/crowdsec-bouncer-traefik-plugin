# Requirement
IssueKey: 2026-09-06-cache-redis-semantics

## Problem
Redis and in-memory cache backends diverge on TTL-zero writes, hide Set/Delete failures from callers, and route reads only through round-robin read hosts—so bans, leases, and captcha grace can appear missing after a successful-looking write. CI covers CRUD only on `localCache`.

## Current (code)
- `pkg/cache/cache.go:69-70` — `localCache.set` forwards `duration` to the TTL heap unchanged; zero is a silent no-op (`pkg/cache/cache_test.go:66`).
- `pkg/cache/cache.go:156-159` — `redisCache.set` forwards `duration` to `writer.Set`; `pkg/simpleredis/simpleredis.go:120-122` always emits `SET … EX <duration>` with no zero guard.
- `pkg/lapi/client_stream.go:115` — stream decisions call `storeStreamDecision` with `int64(duration.Seconds())`, producing zero-second TTLs for sub-second CrowdSec durations.
- `pkg/cache/cache.go:156-165` — Redis `set`/`delete` log errors and return nothing; `pkg/cache/cache.go:232-236` and `:212-216` expose `Set`/`Delete` without error returns.
- `pkg/cache/cache.go:105-106`, `:137` — `get`/`getMany` use `nextReader()` only; writer is fallback when `len(readers)==0` (`pkg/cache/cache.go:96-103`).
- `pkg/lapi/client.go:177-184` — production wiring passes separate write and read Redis hosts.
- `pkg/cache/cache_test.go:15-51`, `:89`, `:247` — CRUD tests construct `localCache` only; `pkg/cache/cache_test.go:266-274` hits Redis only for unreachable `MGet`.
- `pkg/captcha/captcha.go:98` — captcha grace uses `cacheClient.Set` without checking persistence; `2026-09-06-captcha-handler-hardening` branch still has void `Set` (`not found` — no landed error-return API yet).

## Desired
- Normalize and document one TTL-zero contract for memory and Redis (reject, clamp, or treat consistently).
- Return `error` from `Client.Set` and `Client.Delete`; update call sites only as required to compile and handle the new signature.
- After a write, reads must not treat a lagging replica miss as empty for that key (read-your-writes via writer or equivalent).
- Add Redis-backend CRUD parity tests (prefixed keys, miss/unreachable mapping, empty value, `GetMany`, TTL-zero, write errors, read-after-write lag).

## Affected
- `pkg/cache/cache.go`, `pkg/cache/cache_test.go` (primary)
- Call sites: `pkg/lapi/client_stream.go`, `pkg/lapi/client_decisions.go`, `pkg/lapi/client_live.go`, `pkg/decisionscope/range.go`, `pkg/captcha/captcha.go` (signature/error handling only unless explore chooses fail-closed behavior per caller)

## Out of scope
- Remediation encoding (`pkg/cache/remediation.go` — tested separately).
- `localCache` mutex / concurrency model.
- Key prefix design (`prefixed` helper).
- Sub-second duration truncation in `pkg/lapi` before cache (cited as production source of zero TTL, not owned here).
- Negative TTL coercion in `pkg/simpleredis` unless cache boundary starts coercing durations.
- Round-robin fairness (`pkg/cache/cache_test.go:140-165` — already tested).
- Redis replication implementation inside `pkg/simpleredis`.

## Unknowns
- Exact TTL-zero rule to adopt (reject vs immediate delete vs pass-through) — explore must decide and document.
- Read-your-writes scope: per-key window vs all reads until ack vs require same host for reads — explore must decide.
- Whether upstream callers (stream lease, decisions, captcha) should fail closed on Set/Delete error in this ticket or only receive the error surface — explore/propose.

## Tensions
- Ticket asks for fail-closed callers but bounds work to `pkg/cache` + minimal call-site updates; full fail-closed wiring in `pkg/lapi`/`pkg/captcha` may be a follow-up.
- Captcha ticket wants observable `Set`; captcha branch has not landed an error return — this ticket owns the API change.
- Read-your-writes vs existing round-robin reader tests (`cache_test.go:168-200`) — behavior change may need test updates.
- Normalizing TTL-zero on memory may change long-standing no-op semantics asserted at `cache_test.go:66`.
