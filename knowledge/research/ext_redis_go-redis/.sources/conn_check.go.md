---
url: https://github.com/redis/go-redis/blob/8010edc761c98482aa804ad3d3c8447a09528715/internal/pool/conn_check.go
title: go-redis pool connCheck
fetched: 2026-09-05
authority: source
ref: github.com/redis/go-redis@8010edc761c98482aa804ad3d3c8447a09528715:internal/pool/conn_check.go
---

Build tag linux || darwin || dragonfly || freebsd || netbsd || openbsd || solaris || illumos.
Imports "syscall".
connCheck peeks the next byte on the socket without consuming it.
