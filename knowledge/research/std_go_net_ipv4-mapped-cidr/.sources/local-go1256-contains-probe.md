---
url: (local)
title: ParseCIDR and IPNet.Contains IPv4-mapped probe
fetched: 2026-09-18
authority: inference
---

Go 1.25.6 on Windows. Temp module. `net.ParseCIDR` / `IPNet.Contains` / `IPNet.String` only.

`::ffff:0:0/96` → IP `0.0.0.0` len=16 To4=true ones=96 bits=128 String=`0.0.0.0/0`. Contains true for `0.0.0.0`, `192.0.2.1`, `::ffff:192.0.2.1`. Contains false for `2001:db8::1`, `::1`, `::`.

`::ffff:192.0.2.0/120` → String=`192.0.2.0/24`. Contains true for `192.0.2.1`, `::ffff:192.0.2.1`. False for `203.0.113.1` and native IPv6.

`::ffff:192.0.2.0/112` → String=`192.0.0.0/16`. `::ffff:192.0.2.1/128` → String=`192.0.2.1/32`.

`::ffff:192.0.2.0/24` → To4=false String=`::/24`. Contains true for `::` and `::1`, false for `192.0.2.1`.
