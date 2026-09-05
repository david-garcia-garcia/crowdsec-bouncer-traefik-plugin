# Explore

## Concepts

```
  Traefik New ctx ── reclaim.Open ── CrowdsecConnection
                                           │ Close()
                                           ▼
                                    cache.Client.Close
                                           │
                                           ▼
                              SimpleRedis.Close  (writer + readers)
                                           │
                         dest (master): idle pool + RESP + MGET
                         leak: Get after Close still dials
```

**In-tree SimpleRedis** (`pkg/simpleredis`): PR #8 pool (max 8, 30s idle, 2s dial, 1s I/O), RESP, `MGet`, `Close` drains idle and refuses to repool. `CrowdsecConnection.Close` already calls `cacheClient.Close`.

**After Close, `borrow` still dials.** `TestCloseDrainsIdleAndDoesNotRepool` asserts a second TCP accept. That is a resource leak on dispose/reload: reclaim fires `Close`, then any stray Get (or a test of “safe to call more than once” that still Gets) opens a socket.

**Official go-redis** (`knowledge/research/ext_redis_go-redis`): Go 1.24, `unsafe` + Linux `syscall`. Yaegi + this plugin’s Go 1.22 cannot take it. `useUnsafe` only unlocks those two stdlib packages; it does not fix go-redis reflection panics ([traefik#11938](https://github.com/traefik/traefik/issues/11938)).

**Reclaim:** dest already closes the cache when the CrowdsecConnection incarnation ends. Do not add a second pool owner.

Measured: `go test ./pkg/cache` previously passed on main; after dest merge the suite includes `pkg/simpleredis` Close redial.

## Decisions

- Dest is `master` (in-tree client already landed in #5). Do not copy v1.0.12 again.
- Do not take go-redis. Do not set `useUnsafe`.
- Close must stop new dials (`errUnreachable`). Update the Close test.
- Add AUTH-once-per-dial, SELECT once-per-dial, I/O timeout, idle-timeout eviction tests.
- Do not rename `do`/`clean` in this change (pin + length). Job comments only on `Close`/`borrow` if the Close contract changes.
- No pipelining, no cache `GetMany`, no Dragonfly e2e.

## Open questions

- Q: Should we replace simpleredis with official `go-redis`?
  Decision: resolved — no. Go 1.24 + unsafe/syscall + Yaegi reflect panic. Keep in-tree client.
  By: explore

- Q: Should we set Traefik `useUnsafe`?
  Decision: resolved — no. RESP client uses `net`/`bufio` only.
  By: explore

- Q: Where does the client live?
  Decision: resolved — already `pkg/simpleredis` on dest `master`.
  By: explore

- Q: Independent of PR #5 in-tree copy?
  Decision: resolved — dest **is** that copy. This change only closes the post-Close redial and fills test gaps.
  By: explore

- Q: Extra optimizations (pipelining, unsafe buffers, rename `do`/`clean`)?
  Decision: resolved — no pipelining/rename. Applied Close-without-redial, Yaegi-safe deadline via `errors.Is`, and no timeout retry on a reused conn.
  By: implement

- Q: Who owns client IP / Host identity?
  Decision: resolved — none in this change. Redis keys stay whatever cache already passes.
  By: explore
