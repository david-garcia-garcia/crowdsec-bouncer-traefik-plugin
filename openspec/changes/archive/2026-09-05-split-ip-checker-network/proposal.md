## Why

`pkg/ip/ip.go` still mixes hop-trust (`Checker`, `PoolStrategy`, `GetRemoteIP`) with one-CIDR `InNetwork`. `GetRemoteIP` and the forwarded-header walk have no package test, so the path every `ServeHTTP` uses can regress without a unit catching it.

## What Changes

- Split `pkg/ip` into `checker.go` (Checker, PoolStrategy, GetRemoteIP) and `network.go` (`InNetwork`). Same package name.
- Add unit tests next to the hop-trust types for `GetRemoteIP` and the forwarded-header walk. Keep existing `InNetwork` and Checker membership tests.
- Specify how `GetRemoteIP` walks the custom forwarded header, then `RemoteAddr`. **Not BREAKING.** No public config keys.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_ip_radix-lookup`: `GetRemoteIP` SHALL walk the custom forwarded header most-recent-first against the trusted-hop pool, then fall back to `RemoteAddr`. Package tests SHALL cover that walk. File layout is design, not a new spec id.

## Impact

- `pkg/ip/ip.go` → `checker.go` + `network.go`; tests split to `checker_test.go` / `network_test.go`.
- `pkg/bouncer` import path unchanged.
- Usage packet `knowledge/devdocs/core_plugin_ip.md` key files.
- `InNetwork` stays in `pkg/ip`. Not `pkg/decisionscope`.
