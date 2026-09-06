# Requirement
IssueKey: 2026-09-05-scope-headers-identity

## Problem
`decisionScopeHeaders` is stored on both `Bouncer` and `CrowdsecConnection` and is omitted from reclaim identity. Two Traefik routers with the same LAPI and different maps share one stream ticker and cache; the first `New` wins.

## Current (code)
- Reclaim key is `crowdsecconnection.Key(config)` from `plugin.go`; identity fields live in `pkg/crowdsecconnection/identity.go` and do not include `DecisionScopeHeaders`.
- `CrowdsecConnection` copies the normalized map in `pkg/crowdsecconnection/connection.go` (`decisionScopeHeaders`) and uses it for stream `scopes=` and ingest in `pkg/crowdsecconnection/connection_decisions.go`.
- `Bouncer` copies the same normalized map again in `pkg/bouncer/bouncer.go` and reads request headers from that copy in `ServeHTTP`.
- `plugin_test.go` `TestNew_SameConnectionFields_ShareIncarnation` asserts two `New` calls with the same LAPI share one connection; there is no test that different maps must not `SameConnection`.
- Usage packet `knowledge/devdocs/core_plugin_decisionscope.md` currently says pass the map into both connection and bouncer, and `_Avoid_: putting Country on the reclaim key`.
- AppSec enable/failure action stay per-router on `Bouncer` (`pkg/bouncer/bouncer.go`); AppSec client/host stay on `CrowdsecConnection` (`pkg/crowdsecconnection/connection.go`). LAPI `scopes=` is per connection (`connection_decisions.go` `streamQuery`).

## Desired
One owner of the normalized map: the reclaim identity / `CrowdsecConnection`. Two `New()` with the same LAPI host and different `decisionScopeHeaders` must not `SameConnection`. `Bouncer` must not keep a second copy; it uses the connection’s map (or request headers without storing a duplicate). AppSec drop flags stay per-route on `Bouncer`; AppSec client/host stay on the connection. Header-mapped scopes belong on connection identity because they change stream `scopes=` and ingest. Tests: two `New()` with same LAPI host and different maps must not `SameConnection`.

## Affected
- `pkg/crowdsecconnection/identity.go`
- `pkg/crowdsecconnection/connection.go` (keep the field; add a getter if bouncer reads it)
- `pkg/bouncer/bouncer.go` (drop the duplicate field)
- `plugin_test.go` (isolation test)
- `knowledge/devdocs/core_plugin_decisionscope.md` and `knowledge/devdocs/core_plugin_middleware.md` (after apply)

## Out of scope
- File-split of `connection.go` (sibling `2026-09-05-split-connection-files`)
- Split of configuration files, IP trust, remediation-code owner, decisionscope mode bool, config Prepare snapshot
- Moving cache remediation constants
- Prepare/CAPI mutation except as needed for identity hashing of the new field
- Changing AppSec FailureBlock / `crowdsecAppsecFailureAction` ownership (stays on Bouncer)
- Changing LAPI stream cursor ownership on CrowdSec (third-party; two connections with the same API key still share a LAPI bouncer row)

## Unknowns
- Whether empty vs omitted `decisionScopeHeaders` must hash as the same identity (both normalize to nil today).
- Whether identity hashes the Traefik-raw map or `NormalizeDecisionScopeHeaders` output (`Country` vs `country`).
- LAPI `stream_cursor` is per bouncer row for the same API key + client IP (`knowledge/research/ext_crowdsec_lapi_stream-cursor/`); two local connections with different maps still share that cursor. Ticket asks for local stream/cache isolation only.

## Tensions
- Ticket vs usage: `core_plugin_decisionscope.md` currently avoids putting Country on the reclaim key; this ticket requires the map on identity so stream `scopes=` cannot be stolen by the first `New`.
- Ticket vs LAPI: local isolation does not create two CrowdSec stream cursors; that is documented third-party behavior, not this change.
