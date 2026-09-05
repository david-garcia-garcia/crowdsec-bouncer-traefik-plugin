# Requirement
IssueKey: 2026-09-05-split-ip-trust

## Problem

`pkg/ip/ip.go` holds two domains: hop-trust (`Checker`, `PoolStrategy`, `GetRemoteIP`) and one-CIDR Range (`InNetwork`). The request path the bouncer uses every time (`GetRemoteIP` plus the trusted pool) has no dedicated unit file next to those types. Callers want physical isolation in the same package and coverage for that hop-trust path. Behavior must not change.

Source: caller spec (`ticket/source.md`). Dest `master` (`2d4acf3`).

## Current (code)

- One source file owns both domains. `Checker` / `NewChecker` / `Contains` / `ContainsIP` / `hostCIDR` (trusted hop and trusted client lists via `pkg/iplookup`). `PoolStrategy` and `getIP` walk the custom forwarded header most-recent-first and return the first address not in the checker. `GetRemoteIP` uses that walk, then `net.SplitHostPort(req.RemoteAddr)` when the header yields nothing. Path: `pkg/ip/ip.go`.
- `InNetwork` answers whether one address sits in one CIDR or equals a bare IP. It shares package-private `parseIP` with `Contains`. Path: `pkg/ip/ip.go`.
- `pkg/ip/ip_test.go` has `TestInNetwork` and also `TestCheckerContains` / `TestCheckerContainsCatchAllFamily` (CIDR hit/miss, bare host, overlapping any-match, empty list, invalid CIDR, IPv4/IPv6 catch-all families). There is no `TestGetRemoteIP` and no X-Forwarded-For / `PoolStrategy.getIP` unit test in this package. Path: `pkg/ip/ip_test.go`.
- Bouncer builds two checkers and two pool strategies at `New`, then each `ServeHTTP` calls `ip.GetRemoteIP` with `serverPoolStrategy` and `Checker.Contains` on `clientPoolStrategy`. Import is `pkg/ip`. Path: `pkg/bouncer/bouncer.go`.
- Plugin-level tests set `X-Forwarded-For` on HTTP requests; they do not unit-test `GetRemoteIP`. Path: `plugin_test.go`.
- Usage packet still names a single `pkg/ip/ip.go`. Path: `knowledge/devdocs/core_plugin_ip.md`.
- Spec `core_plugin_ip_radix-lookup` already requires Checker membership and that client IP comes from `GetRemoteIP`. It does not require a file split. Path: `openspec/specs/core_plugin_ip_radix-lookup/spec.md`.

## Desired

- Hop-trust types (`Checker`, `PoolStrategy`, `GetRemoteIP`) in one file in `pkg/ip` (example names: `trust.go`).
- `InNetwork` in another file in the same package, keeping the existing `TestInNetwork` cases.
- Unit tests next to the hop-trust types for `GetRemoteIP`, `Checker.Contains`, and the X-Forwarded-For walk. Existing Checker tests may move with the type; they already exist.
- Same package name `ip`. No bouncer call-site change unless a file move forced an import path (it must not).
- Behavior unchanged.

## Affected

- `pkg/ip/ip.go` — split into hop-trust vs `InNetwork` files
- `pkg/ip/ip_test.go` — keep `InNetwork` tests; add or colocate hop-trust tests
- `knowledge/devdocs/core_plugin_ip.md` — key files list after the split
- `openspec/specs/` — file-split / hop-trust tests (propose)

## Out of scope

- Renaming package `ip`.
- Moving `InNetwork` into `pkg/decisionscope`.
- Changing bouncer call sites or `GetRemoteIP` / Checker behavior.
- Sibling tickets: 2026-09-05-split-connection-files, 2026-09-05-split-configuration-files, 2026-09-05-scope-headers-identity, 2026-09-05-remediation-codes-owner, 2026-09-05-decisionscope-mode-bool, 2026-09-05-config-prepare-snapshot.
- Changing `pkg/iplookup` or Range membership Helpers on the connection.

## Unknowns

- Exact file names (`trust.go` vs another stem) and where package-private `parseIP` lives.
- Whether `ip.go` remains as a package-comment stub or is deleted after the split.
- Whether existing Checker tests stay in `ip_test.go` or move to a trust test file.

## Tensions

- Ticket says only `InNetwork` has a unit test in `pkg/ip/ip_test.go`. Dest `master` already has `TestCheckerContains` and `TestCheckerContainsCatchAllFamily`. The real gap is `GetRemoteIP` and the forwarded-header walk, not Checker membership.
- File names are examples (`trust.go` vs `network.go`); commandments want the file named for the type, not a vague domain nickname.
