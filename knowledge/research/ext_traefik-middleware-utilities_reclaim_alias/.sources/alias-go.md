---
url: https://github.com/david-garcia-garcia/traefik-middleware-utilities/blob/42e6a1a967155318023c4defe491d1d423e165b6/reclaim/alias.go
title: reclaim/alias.go
fetched: 2026-09-24
authority: source
ref: github.com/david-garcia-garcia/traefik-middleware-utilities@42e6a1a967155318023c4defe491d1d423e165b6:reclaim/alias.go
---

SetAlias, Watch, and ClearPublisher expose a public alias for a mapped key.

Exported types: Watcher { Value *atomic.Value }, Box { Value any }, Published { Value any }.

SetAlias(key, alias, publisher, group) error — second publisher rejected; same publisher may replace its own alias in the same group; empty key/alias/nil table returns nil.

Watch(ctx, alias, empty, changed) — panics on nil ctx; never waits; never binds a holder; first non-nil empty sticks; changed receives Published; nil changed skips; same value does not call again; changed must not re-enter the table (lock held); ctx done drops the subscriber.

ClearPublisher(publisher, group) — drops aliases this publisher still holds in group; watchers stay.

git blob SHA: 0c17dd98a822ab7a6d1b86dc1e75b84ffe64951c
