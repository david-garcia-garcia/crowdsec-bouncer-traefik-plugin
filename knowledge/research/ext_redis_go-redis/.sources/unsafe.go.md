---
url: https://github.com/redis/go-redis/blob/8010edc761c98482aa804ad3d3c8447a09528715/internal/util/unsafe.go
title: go-redis BytesToString via unsafe
fetched: 2026-09-05
authority: source
ref: github.com/redis/go-redis@8010edc761c98482aa804ad3d3c8447a09528715:internal/util/unsafe.go
---

Build tag !appengine.
Imports "unsafe".
BytesToString uses unsafe.String(unsafe.SliceData(b), len(b)).
StringToBytes uses unsafe.Slice(unsafe.StringData(s), len(s)).
