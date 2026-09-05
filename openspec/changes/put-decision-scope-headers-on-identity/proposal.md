## Why

On master, `decisionScopeHeaders` is copied onto both `Bouncer` and `CrowdsecConnection` and is omitted from reclaim identity. Two Traefik routers with the same LAPI and different maps share one stream ticker and cache; the first `New` wins, so the second route’s Country/AS ingest never lands.

## What Changes

- Put the **normalized** `decisionScopeHeaders` map on CrowdsecConnection reclaim identity (`identityFrom` / `Key`).
- Drop the duplicate field on `Bouncer`. Request lookup reads the connection’s map.
- Two `New()` with the same LAPI host and different maps MUST NOT `SameConnection`.
- Empty and omitted maps stay the same identity (normalized nil → stream `ip,range`).
- Do not file-split `connection.go`. Do not change Prepare/CAPI routing except hashing the new field. Do not move cache remediation constants.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_instance-reclaim`: Reclaim identity includes the normalized `decisionScopeHeaders` map. Different maps are different CrowdsecConnections.
- `core_plugin_decisions_scopes`: The connection owns the header map used for stream `scopes=` and ingest. The bouncer MUST NOT store a second copy; it reads the connection’s map for request headers.

## Impact

- `pkg/crowdsecconnection/identity.go` — add normalized map to identity.
- `pkg/crowdsecconnection/connection.go` — keep the live field; add `DecisionScopeHeaders()`.
- `pkg/bouncer/bouncer.go` — drop the duplicate; `RequestScopeValues(conn.DecisionScopeHeaders(), req)`.
- `plugin_test.go` — two `New()` same LAPI, different maps, not `SameConnection`.
- Usage packets `core_plugin_middleware.md` and `core_plugin_decisionscope.md` (after apply).
