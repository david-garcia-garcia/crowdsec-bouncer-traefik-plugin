# Requirement
IssueKey: 2026-09-05-decisionscope-mode-bool

## Problem
`pkg/decisionscope` (matching) imports `pkg/configuration` (Traefik plugin DTO) only so `LookupCachedRemediation` can compare a mode string to `StreamMode` / `AloneMode` before using range membership. Matching should not know that config bag.

## Current (code)
- `LookupCachedRemediation` takes `mode string` and sets `useRangeMembership := mode == configuration.StreamMode || mode == configuration.AloneMode`. Path: `pkg/decisionscope/lookup.go`.
- That is the only `configuration` import in the package. Path: `pkg/decisionscope/lookup.go`.
- ServeHTTP passes `b.conn.Mode()` into lookup. Stream/alone vs live/none is decided inside decisionscope. Path: `pkg/bouncer/bouncer.go`.
- Tests pass `"stream"` / `"none"` as the mode argument. Path: `pkg/decisionscope/range_test.go`.
- Mode constants live on the Traefik config package. Path: `pkg/configuration/configuration.go`.
- `CrowdsecConnection.Mode()` returns the stored mode string. Path: `pkg/crowdsecconnection/connection.go`.

## Desired
- `LookupCachedRemediation(cache, useRangeIndex bool, remoteIP, scopes, membership)` — callers that know the mode pass true for stream/alone.
- `pkg/decisionscope` Go imports no longer include `configuration`.
- Call sites updated: bouncer ServeHTTP and tests.

## Affected
- `pkg/decisionscope/lookup.go` — signature and import.
- `pkg/decisionscope/range_test.go` — call sites.
- `pkg/bouncer/bouncer.go` — ServeHTTP call site.
- Usage packet `knowledge/devdocs/core_plugin_decisionscope.md` (example still passes `mode`).

## Out of scope
- Moving remediation constants (`BannedValue` / `CaptchaValue` stay on cache; sibling `2026-09-05-remediation-codes-owner`).
- Splitting `connection.go` or `configuration.go`.
- Changing identity / scope headers (`2026-09-05-scope-headers-identity`).
- Split-ip-trust, split-connection-files, split-configuration-files, config-prepare-snapshot.
- Dropping the existing `*RangeMembership` argument (ticket Desired line omitted it; that argument is already the Range owner).

## Unknowns
- Exact bool name (`useRangeIndex` vs a name that matches membership, not the old blob).
- Whether ServeHTTP computes the bool inline from `Mode()` or a connection helper is added.

## Tensions
- Ticket Desired signature omits `membership *RangeMembership`, which already exists and must stay (range lookup is not a blob Get). Keep membership; only replace the mode string with a bool.
- Ticket says `useRangeIndex`; current body uses membership, not the range-index blob. Name is a later-phase choice; behavior is the existing stream/alone branch.
