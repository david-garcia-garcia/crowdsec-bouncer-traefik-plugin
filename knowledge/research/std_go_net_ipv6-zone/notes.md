# IPv6 zone ID parse

How Go treats an RFC 4007 scoped IPv6 address (`fe80::1%eth0`) on `net.ParseIP`, `net.SplitHostPort`, `TCPAddr.String`, and `netip.ParseAddr`.

Fetched: 2026-09-18. Pin: Go 1.25.6 (`go version go1.25.6 windows/amd64`).

## `net.ParseIP` rejects a zone

Official forms are IPv4 dotted decimal, IPv6, and IPv4-mapped IPv6. A zone is not listed. A string that is not a valid textual IP returns nil. ([ParseIP](https://pkg.go.dev/net#ParseIP); extract `.sources/parseip.md`)

Source on this pin: `ParseIP` calls unexported `parseIP`, which uses `netip.ParseAddr` and then returns invalid when `err != nil` **or** `ip.Zone() != ""`. A zoned address that `netip` accepts is still nil from `net.ParseIP`. (`golang/go@go1.25.6:src/net/ip.go`; extract `.sources/ip.go.md`)

Local probe: `net.ParseIP("fe80::1%eth0")` is nil; `net.ParseIP("fe80::1")` is `fe80::1`. (authority: inference — `.sources/local-go1256-zone-probe.md`)

## `netip.ParseAddr` accepts a zone

`ParseAddr` lists IPv6 with a scoped zone as a valid form (`fe80::1cc0:3e8c:119f:c2e1%ens18`). `WithZone("")` removes it. `As16` returns the 16-byte address without the zone. ([ParseAddr](https://pkg.go.dev/net/netip#ParseAddr); extract `.sources/parseaddr.md`)

`net.ParseIP` is not a wrapper that keeps that zone. It is a filter that drops it.

## `SplitHostPort` keeps `host%zone`

`SplitHostPort` documents `[host%zone]:port` and returns `host%zone` plus port. A literal IPv6 host must stay bracketed, as in `[fe80::1%zone]:80`. ([SplitHostPort](https://pkg.go.dev/net#SplitHostPort); extract `.sources/splithostport.md`)

Local probe: `SplitHostPort("[fe80::1%eth0]:443")` → host `fe80::1%eth0`, port `443`, err nil. (authority: inference — `.sources/local-go1256-zone-probe.md`)

## `TCPAddr.String` writes `[ip%zone]:port`

When `Zone != ""`, `TCPAddr.String` is `JoinHostPort(ip+"%"+zone, port)`. `JoinHostPort` brackets a host that contains a colon. (`golang/go@go1.25.6:src/net/tcpsock.go`; extract `.sources/tcpsock.go.md`)

That is the `req.RemoteAddr` text a Go `net/http` server sets from `conn.RemoteAddr().String()` for a link-local IPv6 peer.

## What this means for a `net.IP` membership check

A hop or `RemoteAddr` host that still has `%zone` cannot be fed to `net.ParseIP`. Strip the zone (or parse with `netip.ParseAddr` and `WithZone("")`) before that call. `net.IP` has no zone field.

## Sources

- Official: [net.ParseIP](https://pkg.go.dev/net#ParseIP), [net.SplitHostPort](https://pkg.go.dev/net#SplitHostPort), [netip.ParseAddr](https://pkg.go.dev/net/netip#ParseAddr)
- Source: `golang/go@go1.25.6:src/net/ip.go`, `golang/go@go1.25.6:src/net/tcpsock.go`
- Extracts: `.sources/`
