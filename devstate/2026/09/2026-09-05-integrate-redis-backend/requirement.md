# Requirement
IssueKey: 2026-09-05-integrate-redis-backend

## Problem
The plugin talks to Redis through the published module `github.com/maxlerebourg/simpleredis` at v1.0.12. That copy is vendored and dials a new connection per command. The caller wants that library **in this tree as a first-party package**, pinned to [simpleredis PR #8](https://github.com/maxlerebourg/simpleredis/pull/8) (idle-connection pool + `MGet`), and wants **real-stack e2e** of a functional Redis-protocol backend using a **Dragonfly** image, not Redis.

## Current (code)
- Module pin: `go.mod` requires `github.com/maxlerebourg/simpleredis v1.0.12`.
- Vendored copy: `vendor/github.com/maxlerebourg/simpleredis/simpleredis.go` — `Get`/`Set`/`Del` only; each command `Dial`s TCP, runs AUTH/SELECT, sends an inline (space-joined) command, closes. No `MGet`. No pool.
- Production caller: `pkg/cache/cache.go` `redisCache` holds `writer simpleredis.SimpleRedis` and `readers []simpleredis.SimpleRedis` **by value**, round-robins with `nextReader()`, maps `redis:miss` / `redis:unreachable` to cache errors. `Client.New` `Init`s one writer plus each `redisCacheReadHosts` entry.
- Unit tests: `pkg/cache/cache_test.go` uses local TTL cache for Get/Set/Delete; `Test_nextReader` allocates `[]simpleredis.SimpleRedis` and compares pointers. No live Redis.
- Lint allowlist: `.golangci.yml` depguard allows `github.com/maxlerebourg/simpleredis` for main and test.
- Mock e2e Redis: `tests/e2e/mock/scenarios/redis/` plus `tests/e2e/mock/mocklapi/main.go` `serveRedis` — a TCP stand-in that parses **inline** `GET ` lines, not RESP arrays. Comment in that file: SET/DEL/AUTH/SELECT get `+OK` and “don't read the response anyway”.
- Real-stack e2e: `tests/e2e/real/docker-compose.test.yml` boots Traefik + Crowdsec + whoami routes. **No Redis/Dragonfly service.** No `redisCacheEnabled` labels. Pester files under `tests/e2e/real/*.Tests.ps1` do not cover a functional Redis cache. CI job `e2e (docker + pester)` in `.github/workflows/e2e.yml` runs that suite.
- Examples: `examples/redis-cache/` uses Redis images for operator demos, not e2e.

## Desired
- Copy [simpleredis PR #8](https://github.com/maxlerebourg/simpleredis/pull/8) (`pool-redis-connections`: pooled connections, RESP arrays, `MGet`, reply/timeout/newline fixes) into this repository as a **local package** (stop depending on the published v1.0.12 module for runtime).
- Keep the plugin cache API (`pkg/cache`) working against that package, including any copy-by-value change the pooled client requires.
- Add real-stack e2e that exercises a **functional** Redis-protocol backend with a **Dragonfly** image (not Redis), proving cache hit/miss/ban paths through Traefik + Crowdsec.

## Affected
- `go.mod` / `go.sum` / `vendor/github.com/maxlerebourg/simpleredis/`
- New in-tree package (path not specified by the ticket)
- `pkg/cache/cache.go`, `pkg/cache/cache_test.go`
- `.golangci.yml` depguard
- `tests/e2e/mock/mocklapi/main.go` (wire format will change if the in-tree client sends RESP)
- `tests/e2e/real/docker-compose.test.yml`, new `tests/e2e/real/*.Tests.ps1`, possibly `Test-Integration.ps1`
- `.github/workflows/e2e.yml` only if the Pester job already picks up new `*.Tests.ps1` (it does via default `-TestPath`)

## Out of scope
- Honouring CrowdSec Range/Country/AS decision scopes (upstream plugin work, not this ticket).
- Merging or tagging upstream `maxlerebourg/simpleredis` PR #8.
- Replacing operator examples (`examples/redis-cache/`) with Dragonfly unless required for the e2e path.
- Restoring PR #8's dropped `Options` / `InitWithOptions` / `Close` API.
- Changing Crowdsec/Traefik image pins except to add Dragonfly.

## Unknowns
- In-tree import path (`pkg/simpleredis` vs another folder).
- Dragonfly image name and tag to pin in compose.
- Whether mock e2e Redis must keep passing after RESP (almost certainly yes — CI runs `make e2e_mock`).
- Whether `MGet` must be called from `pkg/cache` in this change, or only shipped inside the in-tree client for later use.

## Tensions
- Ticket says “integrate as a package”; published v1.0.12 is already vendored. In-tree copy vs `replace` to the PR branch: ticket wants the former so Yaegi/local-plugin load does not depend on an untagged remote.
- PR #8 warns `SimpleRedis` must not be copied by value (mutex). This tree copies values into `readers []simpleredis.SimpleRedis` (`pkg/cache/cache.go`).
- Mock Redis speaks the **old** inline protocol; PR #8 sends RESP arrays. Shipping the pooled client without updating `serveRedis` will fail `tests/e2e/mock/scenarios/redis`.
- User dest is **master**; `origin/HEAD` is `main`. PRs and CI `pull_request` still run; `on.push.branches` is `[main]` only.
