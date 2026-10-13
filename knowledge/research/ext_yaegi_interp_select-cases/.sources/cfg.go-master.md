---
url: https://github.com/traefik/yaegi/blob/fcb76d1ece0c3edc2548c39aa5b170475d2261bb/interp/cfg.go
title: interp/cfg.go selectStmt and setExec (yaegi master 2026-09-26)
fetched: 2026-09-26
authority: source
ref: github.com/traefik/yaegi@fcb76d1ece0c3edc2548c39aa5b170475d2261bb:interp/cfg.go
---

Master still assigns `n.child[0].gen = _select` on `selectStmt` (around 1987). Range over channel still sets `n.anc.gen = rangeChan`. `setExec` still calls `n.gen(n)` once per node after `n.exec` is unset (comment: recursively sets the node exec builtin by walking the CFG).
