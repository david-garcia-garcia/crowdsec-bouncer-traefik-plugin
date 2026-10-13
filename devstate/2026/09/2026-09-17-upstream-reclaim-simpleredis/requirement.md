# Requirement
IssueKey: 2026-09-17-upstream-reclaim-simpleredis

## Problem
In-tree `pkg/reclaim` and `pkg/simpleredis` are ad-hoc forks that drift from the shared utilities repository the author maintains for Traefik middleware work.

## Current (code)
- `pkg/reclaim/` — three Go files (`default.go`, `table.go`, `table_test.go`); package helpers `Default`, `Open`, `OpenWithGrace`, `Peek`, `PeekLivePrefix`; `Table.Open` takes `create func() (any, error)` and optional `Sleep`/`Wake`/`Close` on stored values (`pkg/reclaim/table.go`, `pkg/reclaim/default.go`).
- `pkg/simpleredis/` — `simpleredis.go` + tests; used by `pkg/cache/cache.go` and `pkg/cache/cache_test.go` via import `github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/simpleredis`.
- Callers: `pkg/lapi/session.go`, `pkg/appsec/session.go`, `plugin_test.go` import `pkg/reclaim`.
- `openspec/specs/core_cache_redis_in-tree-client/spec.md` — requires in-tree client, forbids published `github.com/maxlerebourg/simpleredis`, and says sources must not be required to match an outside simpleredis repo.
- `knowledge/research/index_ext_simpleredis.md` — states plugin owns `pkg/simpleredis` and does not treat maxlerebourg/simpleredis as upstream.
- Upstream utilities (research `knowledge/research/ext_traefik-middleware-utilities_packages/notes.md`) — packages at repo root `reclaim/`, `simpleredis/` under module `github.com/david-garcia-garcia/traefik-middleware-utilities`; reclaim `Open` uses explicit `Hooks`; larger test and command surface than in-tree copies.

## Desired
Replace ad-hoc `pkg/reclaim` and `pkg/simpleredis` with upstream versions from `https://github.com/david-garcia-garcia/traefik-middleware-utilities`.

## Affected
- `pkg/reclaim/`, `pkg/simpleredis/`
- `pkg/cache/`, `pkg/lapi/session.go`, `pkg/appsec/session.go`, `plugin_test.go`
- Spec `core_cache_redis_in-tree-client` and related OpenSpec history under `openspec/changes/archive/2026-09-05-simpleredis-*`

## Out of scope
- Unrelated packages on `master` (LAPI stream, captcha, appsec) unless broken by the swap.
- Adopting every command in upstream simpleredis beyond what cache uses today.
- Merging `origin/main` (those packages are absent there; dest is `master`).

## Unknowns
- Whether “replace” means vendored copy into `pkg/` with module path unchanged, `go.mod` require+replace of the utilities module, or submodule/sync script — not specified in ticket.
- Whether reclaim call sites must migrate from value `Sleep`/`Wake`/`Close` to upstream `Hooks` API.

## Tensions
- Ticket asks to align with traefik-middleware-utilities; live spec and research index say in-tree simpleredis must not track an outside repo.
- Upstream reclaim `Open` signature differs from in-tree `Table.Open` (hooks parameter vs optional methods on values).
- `destBranch` is `master` (packages present); `origin/main` lacks `pkg/reclaim` and `pkg/simpleredis`.
