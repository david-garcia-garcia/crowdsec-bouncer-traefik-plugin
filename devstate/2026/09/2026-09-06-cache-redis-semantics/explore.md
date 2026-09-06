# Explore
IssueKey: 2026-09-06-cache-redis-semantics

## Concepts

```
Set/Delete (writer) ──▶ redis primary
                              │
                              │ replication lag
                              ▼
Get/GetMany (readers) ◀── redis replica(s)  ← can miss just-written keys
```

Memory backend has no writer/reader split; TTL heap ignores `duration <= 0`; Redis always sent `SET … EX n`.

## Decisions

1. **TTL zero contract:** `duration <= 0` is a no-op on both backends — skip the write, return `nil`. Matches existing memory semantics (`cache_test.go:66`) and stops Redis from receiving `EX 0`. Document on `Client.Set`.
2. **Set/Delete errors:** `Client.Set` and `Client.Delete` return `error`. Redis propagates `simpleredis` errors (still logged at debug/error). Memory always returns `nil`. Call sites updated only to compile (`_ =` acceptable); fail-closed wiring in `pkg/lapi` / `pkg/captcha` is a follow-up (`issues.md`).
3. **Read-your-writes:** Process-local `sync.Map` on `redisCache` tracks keys successfully written this instance. `Get` routes to `writer` when the key is tracked; `GetMany` uses `writer` when any requested key is tracked. `Delete` removes the key from the map. No time window — until delete or process exit. Round-robin among readers unchanged for untracked keys.

## Open questions

- Q: Exact TTL-zero rule to adopt (reject vs immediate delete vs pass-through)?
  Decision: assumed — `duration <= 0` no-op on both backends; document on `Set`.
  By: explore

- Q: Read-your-writes scope: per-key window vs all reads vs require same host?
  Decision: assumed — per-key writer routing via in-process write set; replicas still used for cold keys.
  By: explore

- Q: Should upstream callers fail closed on Set/Delete error in this ticket?
  Decision: assumed — this ticket lands the error return only; callers compile with `_ =` or existing log paths; stream lease / captcha fail-closed is a follow-up issue.
  By: explore
