---
url: https://github.com/golang/go/blob/go1.25.6/src/net/ip.go
title: net.ParseIP and unexported parseIP
fetched: 2026-09-18
authority: source
ref: golang/go@go1.25.6:src/net/ip.go
---

ParseIP: if unexported parseIP(s) is valid, return IP(addr[:]); else nil.

Unexported parseIP: `ip, err := netip.ParseAddr(s)`; if err != nil **or** `ip.Zone() != ""`, return invalid. Else return `ip.As16()`.

A zoned address that netip accepts is rejected here.
