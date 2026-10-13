# Requirement
IssueKey: 2026-09-06-directed-refactor

## Problem
There is no named product gap. The caller wants a GitHub review branch for directed, ad-hoc readability refactors of this Traefik Crowdsec bouncer. Each hunk is a small explore, then a direct apply. OpenSpec propose and openspec-apply-change are out of this run’s cadence.

## Current (code)
- Dest for this fork’s plugin work is `origin/master` (`plugin.go`, `pkg/bouncer/`). `origin/HEAD` is `main`; `git ls-tree origin/main` has no `pkg/bouncer` (that tree is 19 commits behind `master`).
- Per-router handler is `pkg/bouncer/bouncer.go` `ServeHTTP` (trusted IP, `crowdsecMode`, cache, live lookup, stream miss). `plugin.go` `New` opens LAPI/AppSec and returns that bouncer.
- `crowdsecMode` is `none` | `live` | `stream` | `alone` | `appsec` in `pkg/configuration/configuration.go`. Default is `live`.
- OpenSpec catalog lives under `openspec/specs/`; in-progress changes under `openspec/changes/`. This ticket does not name a spec leaf to change.
- A specific readability defect or target hunk was not named: not found.

## Desired
- One branch `2026-09-06-directed-refactor` from `master`, stub GitHub PR, `devstate/` bus.
- Skip OpenSpec propose and apply. Do not open `openspec/changes/` unless a later explore names a spec gap.
- For each later refactor: a small explore, then apply the hunk. No new public Traefik keys. No behavior change unless that explore names one.

## Affected
- Unknown until the first refactor is named. Cursor was on `pkg/bouncer/bouncer.go` when the bus started; that is not a named hunk.

## Out of scope
- OpenSpec propose / openspec-apply-change / archive of a change folder for this bus.
- New CrowdsecMode values, LAPI/AppSec protocol, or operator keys.
- A full eight-phase run per small hunk.
- Switching dest to `main` (`origin/HEAD`).

## Unknowns
- First (and later) hunks are not named.
- Whether each apply is one commit or several.
- When the stub PR drops WIP vs stays open across several hunks.

## Tensions
- `sbs-dev-workflow` eight-phase run includes propose and implement-as-apply. The caller set cadence to skip those and apply after each small explore.
- `origin/HEAD` is `main`; dest is `master` because that is where this plugin tree lives (same as sibling tickets).
