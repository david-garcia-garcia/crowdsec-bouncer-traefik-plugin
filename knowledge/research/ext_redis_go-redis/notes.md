# go-redis client

Official Go client for Redis. Module `github.com/redis/go-redis/v9`.

Pinned for this finding: `github.com/redis/go-redis@8010edc761c98482aa804ad3d3c8447a09528715` (committed 2026-09-03).

## Official status

`go-redis` is the client Redis documents for Go. The redis.io client guide names `go-redis` as "the Go client for Redis" and installs it with `go get github.com/redis/go-redis/v9`.
Source: <https://redis.io/docs/latest/develop/clients/go/> (extract: `.sources/redis-io-go-client-guide.md`).

The same page's client legend lists exactly one Go client (`Go: go-redis client`). It does **not** mention `github.com/gomodule/redigo`. No redigo fallback is recorded here, because official Redis documentation no longer names it. Source: same page.

## Go version floor

`go.mod` declares `go 1.24`.
Source: `redis/go-redis@8010edc:go.mod`.

redis.io states the client "supports the last two Go versions".
Source: <https://redis.io/docs/latest/develop/clients/go/>.

This is a hard constraint for any host pinned below Go 1.24. It is stricter than the Traefik-plugin toolchain of this repo, whose `go.mod` declares `go 1.22.12` (`crowdsec-bouncer-traefik-plugin:go.mod`, `authority: source`).

## Dependencies

Direct requires in the root module `go.mod`, all in one block:

| module | version |
|---|---|
| `github.com/bsm/ginkgo/v2` | v2.12.0 |
| `github.com/bsm/gomega` | v1.27.10 |
| `github.com/cespare/xxhash/v2` | v2.3.0 |
| `github.com/zeebo/xxh3` | v1.1.0 |
| `go.uber.org/atomic` | v1.11.0 |
| `golang.org/x/sys` | v0.30.0 |

One indirect: `github.com/klauspost/cpuid/v2 v2.2.10`. `go.sum` pins 22 distinct modules in total (test and transitive included).
Source: `redis/go-redis@8010edc:go.mod`, `redis/go-redis@8010edc:go.sum`.

Sub-packages under `extra/` (`rediscmd`, `redisotel`, `redisprometheus`, `rediscensus`, `redisotel-native`) and every directory under `example/` are **separate Go modules** with their own `go.mod`. They are not pulled in by requiring the root module.
Source: `redis/go-redis@8010edc:extra/*/go.mod`, `redis/go-redis@8010edc:example/*/go.mod`.

## Package surface

Client construction, in package `redis`:

- `func NewClient(opt *Options) *Client` — `redis.go:2081`
- `func ParseURL(redisURL string) (*Options, error)` — `options.go:740`
- `type Options struct` — `options.go:49`
- `type Client struct` — `redis.go:2064`

Commands are methods on `cmdable`, promoted onto `*Client`. Every one takes `ctx context.Context` first and returns a typed command value rather than `(value, error)`:

| method | signature | file:line |
|---|---|---|
| `Get` | `(ctx, key string) *StringCmd` | `string_commands.go:139` |
| `Set` | `(ctx, key string, value any, expiration time.Duration) *StatusCmd` | `string_commands.go:478` |
| `SetEx` | `(ctx, key string, value any, expiration time.Duration) *StatusCmd` | `string_commands.go:579` |
| `SetNX` | `(ctx, key string, value any, expiration time.Duration) *BoolCmd` | `string_commands.go:611` |
| `MGet` | `(ctx, keys ...string) *SliceCmd` | `string_commands.go:389` |
| `MSet` | `(ctx, values ...any) *StatusCmd` | `string_commands.go:405` |
| `Del` | `(ctx, keys ...string) *IntCmd` | `generic_commands.go:51` |
| `Expire` | `(ctx, key string, expiration time.Duration) *BoolCmd` | `generic_commands.go:90` |
| `TTL` | `(ctx, key string) *DurationCmd` | `generic_commands.go:341` |

Results are taken with `.Err()` or `.Result()` on the returned command. A missing key surfaces as the sentinel `redis.Nil` (`const Nil = proto.Nil`, `redis.go`), not as a zero value.
Source: `redis/go-redis@8010edc` at the paths listed above; idiom confirmed by <https://redis.io/docs/latest/develop/clients/go/>.

### Pooling

Connection pooling is built in and configured on `Options` — there is no separate pool type to wire up. Fields (`options.go`): `DialTimeout` (133), `ReadTimeout` (155), `PoolSize` (301), `PoolTimeout` (313), `MinIdleConns` (319), `MaxIdleConns` (325), plus `PipelinePoolSize` (278) for the separate pipeline pool.
Source: `redis/go-redis@8010edc:options.go`.

## Restricted imports: `unsafe` and `syscall`

Both are present on the mandatory import path of the root module. This is the decisive constraint for any interpreted host.

**`unsafe`** — `internal/util/unsafe.go:6`, build tag `//go:build !appengine`. It provides `BytesToString` / `StringToBytes` via `unsafe.String`, `unsafe.SliceData`, `unsafe.Slice`, `unsafe.StringData`.
There is a build-tagged escape: `internal/util/safe.go` (`//go:build appengine`) implements the same two functions with plain `string(b)` / `[]byte(s)` conversions. Building with `-tags appengine` therefore removes this `unsafe` import from the module.

`internal/util` is reachable from the root package — imported by `command.go:21`, `options.go:22`, and `internal/proto/reader.go:12` (also `json.go`, `timeseries_commands.go`, `internal/arg.go`, `internal/hscan/structmap.go`, `internal/proto/writer.go`, `internal/proto/scan.go`, `internal/routing/aggregator.go`, `helper/helper.go`). It is not optional.

The other `unsafe` in the tree, `extra/rediscmd/unsafe.go:6`, is in a **separate module** and is irrelevant to a root-module dependency.

**`syscall`** — `internal/pool/conn_check.go:9`, build tag `//go:build linux || darwin || dragonfly || freebsd || netbsd || openbsd || solaris || illumos`. It calls `syscall.Recvfrom` with `syscall.MSG_PEEK|syscall.MSG_DONTWAIT` through `syscall.Conn` / `RawConn.Read` to detect dead or readable idle connections without consuming bytes.
Fallback exists for other platforms only: `internal/pool/conn_check_dummy.go` (`//go:build !linux && !darwin && ...`) stubs `connCheck`, `maybeHasData`, and `checkForData` to no-ops. There is **no** build tag that disables the syscall path on Linux, which is where Traefik runs.

`internal/pool` is imported by root-package `redis.go:18`, plus `autopipeline.go`, `osscluster.go`, and `error.go`. Also not optional.

**`golang.org/x/sys/cpu`** — imported directly by the root package at `autopipeline.go:15`. Not stdlib `syscall`, but a third-party low-level package that an interpreter must also resolve.

Source for this whole section: `redis/go-redis@8010edc` at the paths and line numbers listed (extract: `.sources/go-redis-repo.md`).

### Consequence

A host that interprets Go and blocks `unsafe`/`syscall` cannot load this module as-is. Building with `-tags appengine` clears `unsafe` but not `syscall` on Linux and not `golang.org/x/sys/cpu`.
`authority: inference` — derived from the build tags and import graph read above; no vendor document states it.

Lifting the import restriction is also not enough on its own. On
[traefik/traefik#11938](https://github.com/traefik/traefik/issues/11938) a reporter got a
go-redis plugin to load with syscall enabled, and it then panicked with
`reflect.Value.Interface: cannot return value obtained from unexported field or method` —
attributed on-thread to Yaegi's handling of modules that use reflection.
`authority: comment` — issue reporters, not maintainers. Extract: `.sources/traefik-issue-11938.md`.

For what a Traefik plugin host requires to admit those imports, see `knowledge/research/ext_traefik_plugins_useunsafe/notes.md`. For the client this repo uses today, see `knowledge/research/ext_simpleredis_client_pooled-mget/notes.md`.
