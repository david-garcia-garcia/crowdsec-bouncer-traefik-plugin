---
url: https://github.com/redis/go-redis/tree/8010edc761c98482aa804ad3d3c8447a09528715
title: redis/go-redis — root module source
fetched: 2026-09-05
authority: source
ref: github.com/redis/go-redis@8010edc761c98482aa804ad3d3c8447a09528715
---

Shallow clone (`git clone --depth 1`) into OS temp, read-only, deleted after extraction.
HEAD commit `8010edc761c98482aa804ad3d3c8447a09528715`, dated 2026-09-03,
subject `fix(client): don't leak pools on NewClient panic (#4003)`.

## go.mod

```
module github.com/redis/go-redis/v9

go 1.24

require (
	github.com/bsm/ginkgo/v2 v2.12.0
	github.com/bsm/gomega v1.27.10
	github.com/cespare/xxhash/v2 v2.3.0
	github.com/zeebo/xxh3 v1.1.0
	go.uber.org/atomic v1.11.0
	golang.org/x/sys v0.30.0
)

require github.com/klauspost/cpuid/v2 v2.2.10 // indirect
```

`go.sum` pins 22 distinct module paths.

Separate modules in-tree (own `go.mod`, not pulled by the root module):
`extra/rediscmd`, `extra/redisotel`, `extra/redisotel-native`, `extra/redisprometheus`,
`extra/rediscensus`, `internal/customvet`, and each directory under `example/`.

## Restricted-import audit (non-test files, root module)

`"unsafe"` — 2 hits, one of which is outside the root module:

- `internal/util/unsafe.go:6`
- `extra/rediscmd/unsafe.go:6` (separate module)

`"syscall"` — 1 hit in root-module non-test, non-tooling code:

- `internal/pool/conn_check.go:9`
- (also `maintnotifications/e2e/cmd/proxy-fi-server/main.go:8`, a test harness binary)

`golang.org/x/sys/cpu` — `autopipeline.go:15` (root package `redis`).

## internal/util/unsafe.go

```go
//go:build !appengine

package util

import (
	"unsafe"
)

// BytesToString converts byte slice to string.
func BytesToString(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// StringToBytes converts string to byte slice.
func StringToBytes(s string) []byte {
	return unsafe.Slice(unsafe.StringData(s), len(s))
}
```

## internal/util/safe.go — the appengine escape hatch

```go
//go:build appengine

package util

func BytesToString(b []byte) string {
	return string(b)
}

func StringToBytes(s string) []byte {
	return []byte(s)
}
```

Directory listing of `internal/util/`: `atomic_max.go`, `atomic_min.go`, `convert.go`,
`strconv.go`, `type.go`, `safe.go`, `unsafe.go` (+ tests). So `-tags appengine` is a
complete, supported swap for the `unsafe` pair.

## internal/pool/conn_check.go

```go
//go:build linux || darwin || dragonfly || freebsd || netbsd || openbsd || solaris || illumos

package pool

import (
	"errors"
	"io"
	"net"
	"syscall"
	"time"
)

func connCheck(conn net.Conn) error {
	_ = conn.SetDeadline(time.Time{})
	sysConn, ok := conn.(syscall.Conn)
	if !ok {
		return nil
	}
	return checkSyscallConn(sysConn)
}

func checkSyscallConn(sysConn syscall.Conn) error {
	rawConn, err := sysConn.SyscallConn()
	if err != nil {
		return err
	}
	var sysErr error
	if err := rawConn.Read(func(fd uintptr) bool {
		var buf [1]byte
		// Use MSG_PEEK to peek at data without consuming it
		n, _, err := syscall.Recvfrom(int(fd), buf[:], syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
		switch {
		case n == 0 && err == nil:
			sysErr = io.EOF
		case n > 0:
			sysErr = errUnexpectedRead
		case err == syscall.EAGAIN || err == syscall.EWOULDBLOCK:
			sysErr = nil
		default:
			sysErr = err
		}
		return true
	}); err != nil {
		return err
	}
	return sysErr
}
```

Also uses `syscall.Conn` in `underlyingSyscallConn`, `needsCscReadProbe`, `needsCscPeriodicProbe`.

## internal/pool/conn_check_dummy.go — non-unix fallback only

```go
//go:build !linux && !darwin && !dragonfly && !freebsd && !netbsd && !openbsd && !solaris && !illumos

package pool

func connCheck(_ net.Conn) error         { return nil }
func maybeHasData(_ net.Conn) bool       { return false }
func checkForData(_ net.Conn) (bool, error) { return false, nil }
func needsCscReadProbe(_ net.Conn) bool  { return true }
func needsCscPeriodicProbe(_ net.Conn) bool { return true }
```

No tag removes the syscall path on Linux.

## Reachability from the root package

`internal/util` is imported by (non-test): `command.go:21`, `options.go:22`, `json.go`,
`timeseries_commands.go`, `internal/arg.go`, `internal/util.go`, `internal/hscan/structmap.go`,
`internal/proto/reader.go:12`, `internal/proto/writer.go`, `internal/proto/scan.go`,
`internal/routing/aggregator.go`, `helper/helper.go`.

`internal/pool` is imported by (non-test): `redis.go:18`, `autopipeline.go`, `osscluster.go`,
`error.go`, `himport.go`, `csc_integration.go`, `internal/otel/metrics.go`,
`internal/auth/streaming/manager.go`, `internal/auth/streaming/conn_reauth_credentials_listener.go`.

`redis.go` import block (root package `redis`):

```go
import (
	"bytes"; "context"; "errors"; "fmt"; "net"; "sync"; "sync/atomic"; "time"

	"github.com/redis/go-redis/v9/auth"
	"github.com/redis/go-redis/v9/internal"
	"github.com/redis/go-redis/v9/internal/auth/streaming"
	"github.com/redis/go-redis/v9/internal/hscan"
	"github.com/redis/go-redis/v9/internal/otel"
	"github.com/redis/go-redis/v9/internal/pool"
	"github.com/redis/go-redis/v9/internal/proto"
	"github.com/redis/go-redis/v9/maintnotifications"
	"github.com/redis/go-redis/v9/push"
)
```

## Public surface used for the notes

```
redis.go:2064          type Client struct
redis.go:2081          func NewClient(opt *Options) *Client
redis.go               const Nil = proto.Nil
options.go:49          type Options struct
options.go:740         func ParseURL(redisURL string) (*Options, error)

string_commands.go:139 func (c cmdable) Get(ctx context.Context, key string) *StringCmd
string_commands.go:389 func (c cmdable) MGet(ctx context.Context, keys ...string) *SliceCmd
string_commands.go:405 func (c cmdable) MSet(ctx context.Context, values ...interface{}) *StatusCmd
string_commands.go:478 func (c cmdable) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *StatusCmd
string_commands.go:579 func (c cmdable) SetEx(ctx context.Context, key string, value interface{}, expiration time.Duration) *StatusCmd
string_commands.go:611 func (c cmdable) SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) *BoolCmd

generic_commands.go:51  func (c cmdable) Del(ctx context.Context, keys ...string) *IntCmd
generic_commands.go:90  func (c cmdable) Expire(ctx context.Context, key string, expiration time.Duration) *BoolCmd
generic_commands.go:341 func (c cmdable) TTL(ctx context.Context, key string) *DurationCmd
```

Pooling fields on `Options` (`options.go`): `DialTimeout` 133, `ReadTimeout` 155,
`PipelinePoolSize` 278, `PoolSize` 301, `PoolTimeout` 313, `MinIdleConns` 319, `MaxIdleConns` 325.
