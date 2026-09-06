# Explore
IssueKey: 2026-09-06-simpleredis-pool-and-resp

## Concepts
- `SimpleRedis` is a per-host pooled TCP client used by `pkg/cache` (`writer` + round-robin `readers`). Traefik request goroutines share each pool.
- `borrow()` / `release()` implement LIFO idle reuse with `maxIdleConns=8`; active dials are uncapped today.
- `Close()` sets `closed`, drains idle, but `borrow()` unlocks before `dial()` — TOCTOU allows post-Close dials.
- `do()` marks conn `reusable=true` whenever `readReply` returns `clean=true`, including `-ERR` replies mapped to `errNoAuth`.
- RESP parser allocates from peer-supplied `$length` and `*count` with no ceiling.
- Cache values are single-byte remediation flags (`t`/`f`/`c`/`d`) or a newline-separated CIDR range index (`range-index` key); largest realistic payload is the range index blob, not multi-megabyte.

## Decisions
- **Close vs dial:** Hold `mu` through the idle scan and any new dial; re-check `closed` while locked immediately before returning a new conn. In-flight commands that already hold a conn still finish per existing Close contract.
- **Active connection cap:** Add `maxOpenConns = maxIdleConns` (8) with an `active` counter under `mu`. When at cap, return `redis:unreachable` (fail-fast) rather than block — matches existing non-blocking pool semantics and avoids Traefik goroutine pile-up.
- **RESP limits:** `maxBulkBytes = 16 * 1024 * 1024` (16 MiB) and `maxArrayCount = 4096`. Over-limit headers return `redis:issue?` with `clean=false` (non-reusable). Legitimate range-index and MGET batches stay well below these.
- **Session-fatal `-ERR`:** Treat `NOAUTH`, `WRONGPASS`, `NOPERM`, `LOADING`, `READONLY`, and `ERR Client sent AUTH` as non-reusable: `do()` returns `reusable=false`, socket closed, not repooled. No automatic redial on LOADING/READONLY — caller retry path in `exec()` already handles dead pooled conns once.
- **Spec host:** Extend existing `core_cache_redis_in-tree-client` spec with pool/RESP hardening requirements rather than a new spec id — same subsystem, same consumers.
- **Tests:** Extend fake server to emit `-ERR`, oversized `$`/`*`, and block dial; add concurrent Close-during-dial, >8 goroutines peak-conn, and post-Close Set/Del/MGet cases.

## Open questions
- Q: Exact max bulk size and array count for cache values (decision blobs, range indexes)?
  Decision: assumed — 16 MiB bulk and 4096 array elements; cache remediation values are 1 byte and range indexes are KB-scale CIDR lists.
  By: explore

- Q: Active-connection policy when cap reached: block vs fail-fast?
  Decision: assumed — fail-fast with `redis:unreachable` when `active >= maxOpenConns`; preserves non-blocking Traefik middleware behavior.
  By: explore

- Q: Whether `-LOADING`/`-READONLY` warrant one redial vs fail-fast?
  Decision: assumed — fail-fast, non-reusable close; `exec()` single retry on dead pooled conn covers transient cases without keeping bad sockets.
  By: explore
