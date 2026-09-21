---
url: https://github.com/traefik/yaegi/tree/master/stdlib/syscall
title: yaegi stdlib — unsafe and syscall symbol tables
fetched: 2026-09-05
authority: source
ref: github.com/traefik/yaegi@master:stdlib/syscall/, stdlib/unsafe/
---

What `i.Use(unsafe.Symbols)` and `i.Use(syscall.Symbols)` actually make available to an
interpreted plugin.

## stdlib/unsafe/

```
go1_21_unsafe.go   (312 bytes)
go1_22_unsafe.go   (293 bytes)
unsafe.go          (2127 bytes)
```

## stdlib/syscall/

Files are generated per Go version and per GOOS/GOARCH, named
`go1_{minor}_syscall_{goos}_{goarch}.go`. Version prefixes present in the directory:

```
go1_21_syscall_*
go1_22_syscall_*
```

For `linux/amd64` the directory holds `go1_21_syscall_linux_amd64.go` and
`go1_22_syscall_linux_amd64.go`. No `go1_23`/`go1_24`/`go1_25` tables exist.

## Symbol presence check — go1_22_syscall_linux_amd64.go

Grepped for the identifiers `internal/pool/conn_check.go` in go-redis needs:

| symbol | present |
|---|---|
| `Recvfrom` | yes |
| `MSG_PEEK` | yes |
| `MSG_DONTWAIT` | yes |
| `EAGAIN` | yes |
| `Conn` | yes |
| `RawConn` | yes |

So the specific syscall surface go-redis' connection health check uses is exported by Yaegi's
generated table for `linux/amd64`, provided `useUnsafe` is on at both the manifest and settings
level. The generated tables stopping at Go 1.22 is a separate constraint from the symbol set.
