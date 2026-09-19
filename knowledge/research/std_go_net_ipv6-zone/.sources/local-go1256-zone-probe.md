---
url: local
title: Go 1.25.6 ParseIP and SplitHostPort zone probe
fetched: 2026-09-18
authority: inference
---

Throwaway `go run` on go1.25.6 windows/amd64 (temp module, not in the product tree).

net.ParseIP("fe80::1%eth0") = nil
net.ParseIP("fe80::1") = fe80::1
SplitHostPort("[fe80::1%eth0]:443") host="fe80::1%eth0" port="443" err=nil
