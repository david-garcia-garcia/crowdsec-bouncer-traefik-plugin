# Pooled SimpleRedis client (PR #8)

Pinned branch `pool-redis-connections` of [maxlerebourg/simpleredis](https://github.com/maxlerebourg/simpleredis), open PR [#8](https://github.com/maxlerebourg/simpleredis/pull/8). HEAD: `f8801cc098d2ae1743a6f82cb1e60a97e9461b7f` (2026-09-04, “add CI running gofmt, vet and the tests”). Compared with `main` at `94fbffdc41f91d0b50ccecf8f77302ed9d4df342`.

Owners: `github.com/maxlerebourg/simpleredis@f8801cc098d2ae1743a6f82cb1e60a97e9461b7f` (this branch) and `github.com/maxlerebourg/simpleredis@94fbffdc41f91d0b50ccecf8f77302ed9d4df342` (`main`). Extracts under `.sources/`.

## Exported API

Package `simpleredis`, module `github.com/maxlerebourg/simpleredis`, Go 1.22, no `require` dependencies.

Owner: `…@f8801cc:go.mod`. Extract: `.sources/go.mod.md`.

Type `SimpleRedis` with methods:

| Method | Signature | Behaviour |
| --- | --- | --- |
| `Init` | `(host, pass, database string)` | Stores dial target, AUTH password, SELECT index. Empty pass or database skips that handshake. |
| `Get` | `(name string) ([]byte, error)` | `GET`. Exactly one bulk element, else `redis:issue?`. |
| `MGet` | `(names []string) ([][]byte, error)` | `MGET`. Empty/`nil` names return `nil, nil` with no round trip. Reply length must equal `len(names)`, else `redis:issue?`. Missing keys are `nil` slots, not `redis:miss`. |
| `Set` | `(name string, data []byte, duration int64) error` | `SET name data EX <duration>`. Returns the reply error (no longer always `nil`). |
| `Del` | `(name string) error` | `DEL name`. Returns the reply error. |

Error **string** constants (and matching `errors.New` values): `RedisUnreachable` (`redis:unreachable`), `RedisMiss` (`redis:miss`), `RedisTimeout` (`redis:timeout`), `RedisNoAuth` (`redis:noauth`), `RedisIssue` (`redis:issue?`). AUTH-class replies (`NOAUTH`, `WRONGPASS`, `NOPERM`, `ERR Client sent AUTH`) map to `redis:noauth`; other `-` replies become `errors.New(text)`.

Owner: `…@f8801cc:simpleredis.go`. Extract: `.sources/simpleredis.go.md`. README example of `Init`/`Set`/`Get`/`Del`: `…@f8801cc:README.md`. Extract: `.sources/README.md`.

`main` has no `MGet`. Owner: `…@94fbffdc:simpleredis.go`. Extract: `.sources/main-simpleredis.go.md`.

## Connection pool

Package constants: `maxIdleConns = 8`, `idleTimeout = 30s`, `dialTimeout = 2s`, `ioTimeout = 1s`.

- LIFO borrow from `idle`. Idle older than `idleTimeout` is closed lazily on borrow. No janitor goroutine.
- `maxIdleConns` caps **kept** connections. A command never waits for a slot; overflow is closed on release.
- `AUTH` (if `pass != ""`) and `SELECT` (if `database != ""`) run only in `dial()`, once per new TCP connection, not before every command.
- `conn.SetDeadline(now+ioTimeout)` on each command.
- One retry: if a **pooled** connection fails mid-command (`reused && !reusable`), `exec` dials fresh and retries once. A newly dialled connection is not retried.

Owner: `…@f8801cc:simpleredis.go` (`borrow`, `release`, `dial`, `exec`, `do`). Tests: 25 sequential `Get`s open 1 connection; 8 goroutines × 20 `Get`s stay at most 8 connections; a closed idle conn is retried and opens a second. Extract: `.sources/simpleredis_test.go.md`.

## Copy-by-value mutex

`SimpleRedis` holds `sync.Mutex` plus `idle []*pooledConn`. README: a `SimpleRedis` is safe for concurrent use and **must not be copied once initialized**.

Owners: `…@f8801cc:simpleredis.go` (struct fields); `…@f8801cc:README.md`. PR #8 additionally warns that copying into a slice shares the mutex incorrectly; that caller note is owned by the PR body, not the library tree. Extract: `.sources/pull-8.md`.

`main`’s `SimpleRedis` has only `host`/`pass`/`database` (no mutex, no pool). Owner: `…@94fbffdc:simpleredis.go`.

## RESP encoding vs `main` inline commands

This branch encodes every command as a RESP array (`*<n>\r\n` then `$<len>\r\n` + bytes + `\r\n` per arg) and reads bulk replies by announced length (`io.ReadFull`). Array replies walk `$` elements; a `$-1` element stays `nil` in that slot.

Owner: `…@f8801cc:simpleredis.go` (`writeCommand`, `readReply`, `readBulk`). Tests store and fetch a newline-delimited `range-index` via `Set`/`Get` and `MGet`. Extract: `.sources/simpleredis_test.go.md`.

`main` joins args with spaces and a trailing `\r\n` (`genRedisArray`) — inline commands, so a key or value with space or CRLF is not a single Redis argument. `GET` then reads the bulk **payload** with `ReadLineBytes`, so a value containing `\n` is truncated to the first line with no error.

Owner: `…@94fbffdc:simpleredis.go` (`genRedisArray`, `GET` case). The truncation consequence for a newline-delimited list is inference from that reader; the PR body states the same example. Extracts: `.sources/main-simpleredis.go.md`, `.sources/pull-8.md`.

## Reply bugs on `main` (fixed on this branch)

1. **`Set`/`Del` never read their reply.** On `main`, both call `askRedis` then `return nil`. The `SET`/`DEL` switch arms send and fall through. A reused connection would desync; this branch reads every reply and returns the error (test: `Set` with duration `-1` surfaces `ERR value is not an integer or out of range`).
2. **Timeout never fires as written.** `waitRedis` and the `GET` loop use `select { case <-time.After(1s): … default: read }`. The `default` arm always wins if a read is attempted immediately; no deadline is set on the connection. This branch uses `SetDeadline` and maps `net.Error.Timeout()` to `redis:timeout`.
3. **Rejected `AUTH` can deadlock `Set`/`Del`.** `waitRedis` sends on `channel`; `Set`/`Del` pass `nil` for that channel. This branch has no channel machinery.

Owners: `…@94fbffdc:simpleredis.go` for the bugs; `…@f8801cc:simpleredis.go` and `simpleredis_test.go` for the fixes. PR #8 enumerates the same three. Extracts: `.sources/main-simpleredis.go.md`, `.sources/simpleredis.go.md`, `.sources/simpleredis_test.go.md`, `.sources/pull-8.md`.

## Yaegi / Traefik

README, tests, and CI on this branch do **not** mention Yaegi or Traefik. CI runs `gofmt`, `go vet`, and `go test -race` on `push` to `main` and on `pull_request`.

Owners: `…@f8801cc:README.md`, `simpleredis_test.go`, `.github/workflows/main.yml`. Extracts: `.sources/README.md`, `.sources/simpleredis_test.go.md`, `.sources/main.yml.md`.

PR #8 claims the suite was also run with `yaegi test` in a GOPATH layout “the way Traefik loads plugin sources.” That claim is owned by the PR body only (`authority: comment`), not by a file in the tree.

Owner: [PR #8](https://github.com/maxlerebourg/simpleredis/pull/8). Extract: `.sources/pull-8.md`.
