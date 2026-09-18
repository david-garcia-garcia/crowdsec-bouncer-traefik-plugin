---
url: https://github.com/golang/go/blob/go1.25.6/src/net/tcpsock.go
title: TCPAddr.String zone suffix
fetched: 2026-09-18
authority: source
ref: golang/go@go1.25.6:src/net/tcpsock.go
---

TCPAddr has IP, Port, and Zone (IPv6 scoped addressing zone).

String: if Zone != "", return JoinHostPort(ip+"%"+Zone, port). Else JoinHostPort(ip, port).

JoinHostPort brackets a host that contains a colon, so a zoned IPv6 TCP peer prints as [ip%zone]:port.
