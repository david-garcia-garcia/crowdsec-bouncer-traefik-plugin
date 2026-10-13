---
ref: github.com/david-garcia-garcia/traefik-middleware-utilities@950b08de86b6fd9ea68ac1d205e17a379ec60522
title: traefik-middleware-utilities
fetched: 2026-09-17
authority: source
---

Module path `github.com/david-garcia-garcia/traefik-middleware-utilities`.
Tag `v1.0.3` is this commit.

Top-level packages `reclaim/` and `simpleredis/` (not `pkg/`).

`reclaim/table.go`: `New(Config) *Table`; `Open(ctx, key, logger, create, Hooks)`; `OpenWithHooks`; `Reset()`. Grace is `Config.Grace` only. No `Default`, `Peek`, `PeekLivePrefix`, `OpenWithGrace`, `Wrapped`.

`reclaim/opentyped.go`: `OpenTyped[T]` function; Yaegi must keep the instantiation as a call expression.

`simpleredis/simpleredis.go`: `New(Config) (*SimpleRedis, error)`; exported `Err*` sentinels and `IsMiss` / `IsUnreachable`.

`simpleredis/commands.go`: `Get`/`MGet`/`Set`/`Del` (and Incr/Expire/…) take `context.Context`.

`simpleredis/config.go`: Host/Pass/Database plus pool and timeout knobs frozen at New.
