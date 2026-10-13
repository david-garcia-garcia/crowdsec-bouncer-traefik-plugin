---
url: (local)
title: go test filename probe
fetched: 2026-09-17
authority: inference
---

Go 1.25.6 on Windows: temp module with probe_test.go (TestA), cache_testzzz_.go (TestZzz), cache_test.gozzz_ (TestGozzz).

go test -v: only TestA ran; PASS.

Second module with only cache_testzzz_.go containing TestZzz: go test -v printed [no test files], exit 0.

Confirms suffix rule: only *_test.go basenames contribute test files; Test* in other .go basenames is not picked up.
