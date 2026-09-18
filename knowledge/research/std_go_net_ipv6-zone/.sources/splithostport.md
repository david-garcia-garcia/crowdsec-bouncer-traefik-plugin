---
url: https://pkg.go.dev/net#SplitHostPort
title: net.SplitHostPort
fetched: 2026-09-18
authority: official
---

SplitHostPort splits "host:port", "host%zone:port", "[host]:port" or "[host%zone]:port" into host or host%zone and port.

A literal IPv6 address in hostport must be enclosed in square brackets, as in "[::1]:80", "[::1%lo0]:80".

Dial docs on the same page: a literal IPv6 host may be "[fe80::1%zone]:80". The zone is RFC 4007 scope.
