---
url: https://github.com/traefik/yaegi/blob/3fbebb36621c03b2981ccee03246ea40455bd792/interp/cfg.go
title: interp/cfg.go selectStmt, rangeChan gen, setExec (yaegi v0.16.1)
fetched: 2026-09-26
authority: source
ref: github.com/traefik/yaegi@3fbebb36621c03b2981ccee03246ea40455bd792:interp/cfg.go
---

`selectStmt` (around 1911): `n.child[0].gen = _select`. Comment: move action to the block so the select node can be an exit point.

Range over channel (around 136–143): if `sc.rangeChanType(n.anc) != nil`, `n.anc.gen = rangeChan`.

`getExec` (2831): if `n.exec == nil`, `setExec(n)`.

`setExec` (2841–2874): walk CFG; skip nodes that already have `n.exec`; end of each visit is `n.gen(n)`. That is the one-time generator call that builds `_select`'s captured `cases` slice.
