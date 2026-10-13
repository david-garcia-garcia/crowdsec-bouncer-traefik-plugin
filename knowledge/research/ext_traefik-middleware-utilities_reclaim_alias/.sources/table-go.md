---
url: https://github.com/david-garcia-garcia/traefik-middleware-utilities/blob/42e6a1a967155318023c4defe491d1d423e165b6/reclaim/table.go
title: reclaim/table.go
fetched: 2026-09-24
authority: source
ref: github.com/david-garcia-garcia/traefik-middleware-utilities@42e6a1a967155318023c4defe491d1d423e165b6:reclaim/table.go
---

Table has aliases map[string]*aliasEntry. slot has aliases []*aliasEntry reverse link for Close.

New initializes aliases map. Peek(key) (any, State, bool) — Awake/Asleep only; busy/gone/missing ok=false; no wait, bind, Wake, or grace stop.

unbindIncarnationLocked runs from endBusySlot, unmapLocked, installCloser, expire (after Close on the unmapped path), and takeAll (Reset).

Reset takeAll clears Table.aliases after unbinding.

git blob SHA: dcc3d85afa8dd59df2f0d8a21620a18f7ab8173c
