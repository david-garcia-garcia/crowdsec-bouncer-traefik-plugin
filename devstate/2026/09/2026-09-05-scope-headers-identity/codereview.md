# Code review
Pin: origin/master...HEAD (2d4acf3...683620b)
Command: git diff origin/master...HEAD -- . ':!devstate' ':!.cursor'
Axes run on the conductor thread (nested Task not used).

## Standards
none

Gotchas checked: `core_plugin_decisionscope.md` (map on identity, no Bouncer copy; do not geolocate); `core_plugin_middleware.md` (normalized map on reclaim key; AppSec failure stays on Bouncer). Diff matches.

## Spec
none

Requirements walked:
- Connection is reclaimed by connection fields not middleware name (includes normalized map; empty/omitted same identity) — `identity.go` `DecisionScopeHeaders` + `NormalizeDecisionScopeHeaders`
- Different decisionScopeHeaders maps are isolated — `plugin_test.go` `TestNew_DifferentDecisionScopeHeaders_IsolatedConnection`
- Header map lives on the connection — `connection.go` getter; `bouncer.go` dropped the field

## Security
none

No new secrets, egress, or fail-open. Header matching still uses the trusted-hop mapped header via `RequestScopeValues`. Client IP still `GetRemoteIP`. Getter returns the stored map (same trust as before).

## Performance
none

Identity hash runs at `New` / reclaim, not per request. The added map is operator-sized (few scopes), not traffic-sized.

## Dead
none

Grep `DecisionScopeHeaders`: production callers `identityFrom` and `Bouncer.ServeHTTP` via `conn.DecisionScopeHeaders()`. Field `c.decisionScopeHeaders` still used in `connection_decisions.go` stream ingest.

## Applied
none.

## Recorded and skipped
none.
