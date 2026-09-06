## Context

Reclaim binds holders to the context passed at `Open`. Failed `New` after a successful open leaves tickers running until Traefik cancels the constructor context. There is no public `Drop` API.

## Goals / Non-Goals

- Goals: cancel orphan reclaim bindings on constructor error; reject appsec-mode pass-through; add plugin constructor tests.
- Non-Goals: change `ValidateParams` matrix, captcha/bouncer ServeHTTP, reclaim table API.

## Decisions

- Use `bindCtx, cancelBind := context.WithCancel(ctx)` for all backend opens. Named return `err` with defer: cancel `bindCtx` when `err != nil`. On success, `bindCtx` remains a child of Traefik ctx for holder lifetime.
- Appsec-mode guard in `plugin.go` only (not centralized in `configuration.go` this ticket).

## Risks / Trade-offs

- Guard in `New` may diverge from future centralized validation — acceptable until a configuration ticket lands.
