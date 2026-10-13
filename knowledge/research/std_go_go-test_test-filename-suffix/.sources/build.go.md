---
url: https://github.com/golang/go/blob/go1.25.6/src/go/build/build.go
title: go/build package loading
ref: golang/go@69801b25b9624c3a678ef87d30771861e7bba51f:src/go/build/build.go
fetched: 2026-09-17
authority: source
---

matchFile skips basenames where strings.HasPrefix(name, "_") or strings.HasPrefix(name, ".").

Only basenames whose extension is .go (or other listed source ext) proceed; others are non-source.

For .go files: isTest := strings.HasSuffix(name, "_test.go").

If isTest (and not external test package), append to p.TestGoFiles; else if normal, append to p.GoFiles.

TestGoFiles and XTestGoFiles are excluded from GoFiles (package comment on Package struct).
