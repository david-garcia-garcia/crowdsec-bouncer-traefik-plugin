---
url: https://github.com/traefik/yaegi/blob/3fbebb36621c03b2981ccee03246ea40455bd792/interp/run.go
title: interp/run.go _select and rangeChan (yaegi v0.16.1)
fetched: 2026-09-26
authority: source
ref: github.com/traefik/yaegi@3fbebb36621c03b2981ccee03246ea40455bd792:interp/run.go
---

Tag v0.16.1 = commit 3fbebb36621c03b2981ccee03246ea40455bd792.

`_select` (lines 3749–3827): allocates `cases := make([]reflect.SelectCase, nbClause+1)` in the generator, not inside `n.exec`. The exec closure writes `cases[i].Chan` / `cases[i].Send` from the current frame, stores `f.done` at `cases[nbClause]`, then `reflect.Select(cases)`. One slice is reused for every execution of that select statement.

`rangeChan` (lines 2876–2897): `value := genValue(n.child[1])` (the channel). Each exec builds `[]reflect.SelectCase{done, {Dir: reflect.SelectRecv, Chan: value(f)}}` and selects on that new list. The receive channel is `value(f)` from this frame, evaluated per execution.
