---
url: (local)
title: io.LimitReader n<=0 probe
fetched: 2026-09-17
authority: inference
---

Go 1.25.6 on Windows. Temp module. `io.ReadAll(io.LimitReader(strings.NewReader("hello"), 0))` printed `bytes="" err=<nil>`. Same for `n=-1`.
