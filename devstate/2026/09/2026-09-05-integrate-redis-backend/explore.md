# Explore
IssueKey: 2026-09-05-integrate-redis-backend

## Concepts

**Published simpleredis** — `github.com/maxlerebourg/simpleredis` v1.0.12, vendored. Each `Get`/`Set`/`Del` dials TCP, AUTH/SELECT, sends an **inline** command, closes. `SimpleRedis` is a host/pass/database struct with no mutex.

**PR #8 client** — branch `pool-redis-connections`. Same `Init`/`Get`/`Set`/`Del` plus `MGet`. Idle pool (`maxIdleConns` 8, `idleTimeout` 30s). Commands are RESP arrays. `SimpleRedis` holds `sync.Mutex` and **must not be copied by value** after `Init`. `Set`/`Del` read their replies. Bulk values are length-framed (newlines survive).

**In-tree package** — copy that client under this module (`pkg/…`) so Yaegi/localPlugins load it from the bind-mounted tree. No `replace` to an untagged remote; drop the published module from `go.mod` / `vendor`.

**Mock Redis** — `tests/e2e/mock/mocklapi` `serveRedis`: scans lines for IPs / `GET `. That matches v1.0.12 inline. It will not parse PR #8 `*2\r\n$3\r\nGET\r\n…`.

**Functional Redis-protocol backend** — a real process speaking GET/SET/DEL (and AUTH/SELECT if used) that the plugin cache writes and reads. Not `serveRedis`. Ticket: **Dragonfly**, not Redis.

**Client IP in tests** — same owner as the real-stack suite: Traefik forwarded headers + plugin `forwardedHeadersTrustedIps`. Tests send `X-Forwarded-For`. Cache keys are that IP (`bouncer.go` `cacheClient.Get(remoteIP)`).

```
  X-Forwarded-For
        │
        ▼
  Traefik (localPlugins) ── plugin cache
        │                      │
        │                      ├── miss → LAPI (Crowdsec)
        │                      └── hit  → Dragonfly GET/SET/DEL
        ▼
  whoami / 403
```

## Decisions

Copy [simpleredis PR #8](https://github.com/maxlerebourg/simpleredis/pull/8) into `pkg/simpleredis` (Apache-2.0 `LICENSE` + `simpleredis.go` + its tests). Point `pkg/cache` at `github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/simpleredis`. Remove `github.com/maxlerebourg/simpleredis` from `go.mod`, `vendor/`, and depguard.

Store `writer` and `readers` as `*simpleredis.SimpleRedis` so the pool mutex is not copied. Do not call `MGet` from `pkg/cache` in this change (cache still one key per request).

Teach `serveRedis` RESP arrays so mock e2e `redis` still passes; keep inline parsing so older traces stay understandable.

Add Dragonfly to `tests/e2e/real/docker-compose.test.yml` and a live-mode route with `redisCacheEnabled`. Pester under `tests/e2e/real/` proves cache hit/miss against that process. Do not put Dragonfly in `tests/e2e/mock/`.

## Open questions

- Q: Where does the in-tree client live?
  Decision: assumed — `pkg/simpleredis`, same layout as `pkg/cache`. Import path is this module plus `/pkg/simpleredis`.
  By: explore

- Q: Copy sources vs `replace` to the PR branch?
  Decision: assumed — copy PR #8 sources into the module. Ticket asked for a package in this project; Yaegi/localPlugins cannot fetch an untagged GitHub branch.
  By: explore

- Q: Must `pkg/cache` call `MGet` now?
  Decision: assumed — no. Ship `MGet` on the package. Cache stays `Get`/`Set`/`Del` until a later change needs multi-key reads.
  By: explore

- Q: How to stop copying `SimpleRedis` by value?
  Decision: assumed — `writer *simpleredis.SimpleRedis` and `readers []*simpleredis.SimpleRedis`. `nextReader` already returns a pointer.
  By: explore

- Q: Dragonfly image and tag for real-stack e2e?
  Decision: assumed — `docker.dragonflydb.io/dragonflydb/dragonfly:v1.40.2` (latest GitHub release 2026-09-03; official registry from [Install with Docker](https://www.dragonflydb.io/docs/getting-started/docker)). Port 6379. `ulimits.memlock: -1`. No password unless the suite needs AUTH.
  By: explore

- Q: What does “functional redis backend” e2e assert?
  Decision: assumed — a live-mode (or stream) whoami route with `redisCacheEnabled` + `redisCacheHost=dragonfly:6379`. Prove: cache miss then LAPI allow; cached allow until TTL; ban then block after TTL; Traefik restart still sees the Dragonfly-held value (in-memory map would miss). Client identity only via `X-Forwarded-For`.
  By: explore

- Q: Must mock e2e Redis keep passing after RESP?
  Decision: assumed — yes. CI `make e2e_mock` includes `tests/e2e/mock/scenarios/redis`. Update `serveRedis` to parse RESP arrays (still accept inline).
  By: explore

- Q: Who already owns the client address the bouncer remediates in these tests?
  Decision: assumed — Traefik `forwardedHeaders` plus plugin `forwardedHeadersTrustedIps`. Cache key is that IP. Do not parse `RemoteAddr` in the harness.
  By: explore

- Q: Pin Dragonfly in operator examples (`examples/redis-cache/`)?
  Decision: assumed — no. Ticket is e2e coverage, not example rewrite.
  By: explore
