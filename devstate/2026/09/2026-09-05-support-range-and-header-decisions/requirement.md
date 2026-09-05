# Requirement
IssueKey: 2026-09-05-support-range-and-header-decisions

## Problem

On this fork's `master`, the bouncer remediates only by exact client IP. CrowdSec LAPI already issues `Range`, `Country`, `AS`, and other scoped decisions. Stream cache stores `decision.Value` as the key and ServeHTTP looks up only `remoteIP`, so a CIDR or header-scoped decision never matches. Upstream [PR 383](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/383) implemented that matching against upstream `main`; this ticket ports it onto `master` and adds real-stack e2e for the new types.

Source: [upstream #271](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/271), [PR 383](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/383), caller (dest `master`, real e2e).

## Current (code)

- ServeHTTP gets `remoteIP` then `Cache().Get(remoteIP)` only. Path: `pkg/bouncer/bouncer.go` (`ServeHTTP`). No header-scope or Range walk.
- Stream/alone writes cache with `decision.Value` as key and deletes the same. `Decision.Scope` is parsed on the struct and never used. Path: `pkg/crowdsecconnection/connection.go` (`handleStreamCache`, `Decision.Scope`).
- Live/none queries LAPI with `?ip=` only and caches under `remoteIP`. Path: `pkg/crowdsecconnection/connection.go` (`handleNoStreamCache`).
- Config has no `decisionScopeHeaders`. Path: `pkg/configuration/configuration.go` (`Config`).
- Cache client is Get/Set/Delete one key. Path: `pkg/cache/cache.go`. In-tree SimpleRedis already has `MGet`. Path: `pkg/simpleredis/simpleredis.go`. Cache has no `GetMany`.
- Real e2e injects only `--ip` decisions and sends only `X-Forwarded-For`. Path: `tests/e2e/real/TestUtils.ps1` (`Add-TestDecision`, `Test-HttpRequest`). Compose middlewares do not set `decisionScopeHeaders`. Path: `tests/e2e/real/docker-compose.test.yml`.
- Mock e2e has no `scope-headers` scenario on `master`. Path: `tests/e2e/mock/scenarios/` (no `scope-headers/`).
- `master` has no `decision_scope.go` / `decision_ranges.go`. `not found` at repo root and under `pkg/`.
- `openspec/specs/` has no `core_bouncer_decisions_scopes`. `not found`.
- Research `ext_crowdsec_decisions_scopes/` exists on `origin/newdecisions`, not on `master`. Path: `knowledge/research/index_ext_crowdsec.md` (only Docker env + cscli IP add/delete).

## Desired

- Port PR 383 behavior onto `master`: Range CIDR containment in stream/alone without new config; header-mapped scopes via public `decisionScopeHeaders`; `Ip`/`Range` rejected as map keys; Country/AS value normalize as in 383; ban wins overlap; no GeoIP in this plugin.
- Land in this tree's layout (`pkg/bouncer`, `pkg/crowdsecconnection`, `pkg/configuration`, `pkg/cache`), not the upstream-main root `bouncer.go`.
- Use in-tree SimpleRedis `MGet` for the multi-key lookup (MASTER already has it; do not keep the published-module GET loop from 383).
- Real-stack e2e covers Range and at least one header-mapped scope (Country or custom) against live Crowdsec, not only mock LAPI.
- Delivery card names [PR 383](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/383), [#271](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/271), and [PR 368](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/368).

## Affected

- `pkg/bouncer/bouncer.go` — request lookup
- `pkg/crowdsecconnection/connection.go` — stream insert/delete and live query
- `pkg/configuration/configuration.go` — `decisionScopeHeaders`
- `pkg/cache/cache.go` — multi-key get
- new decision-scope / range-index units (place per commandments)
- `tests/e2e/real/` — Pester + TestUtils + compose labels
- `tests/e2e/mock/` — keep mock coverage if 383 had it
- `README.md` — public key
- `openspec/specs/` — decision-scope spec (propose)
- `knowledge/research/` — bring `ext_crowdsec_decisions_scopes` onto this branch

## Out of scope

- Closing or merging upstream [PR 368](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/368) or retargeting [PR 383](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/383) itself.
- Reusing fork [PR 3](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/3) (`newdecisions` → `main`).
- GeoIP lookup inside this plugin.
- Radix-tree Range index (follow-up on 383).
- Changing in-tree SimpleRedis beyond using `MGet` that already exists.

## Unknowns

- Whether `cscli decisions add --range` / `--scope Country` on Crowdsec `v1.7.8` in `tests/e2e/real` is enough to inject Range and Country, or Country needs `--scope` plus a profile.
- How real e2e supplies Country/AS without geoblock: likely extra `Test-HttpRequest` headers plus compose `decisionScopeHeaders`, not a new feeder container.
- Exact file placement of decision-scope code under Yaegi + the `pkg/bouncer` split (383 kept some files in the plugin package for Yaegi).

## Tensions

- PR 383 was written against upstream `main` with root `bouncer.go`. `master` split the plugin into `plugin.go` + `pkg/bouncer` + `pkg/crowdsecconnection`. Cherry-pick will not apply cleanly.
- PR 383 looped Redis `GET` because CI vendored published `simpleredis` v1.0.12. `master` vendors in-tree `pkg/simpleredis` with `MGet`.
- PR 368 is a competing stream-only Range cache on upstream; it keys off `/` in `decision.Value` and does not honor `Decision.Scope`. Do not merge it into `master`.
- PR 383 mock `scope-headers` is not real e2e. Caller requires `tests/e2e/real/` coverage.
