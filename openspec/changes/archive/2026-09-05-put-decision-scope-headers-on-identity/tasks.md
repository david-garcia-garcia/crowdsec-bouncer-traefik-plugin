## 1. Identity

- [x] 1.1 Add the normalized `decisionScopeHeaders` map to `identity` / `identityFrom` (`NormalizeDecisionScopeHeaders`, not the Traefik-raw map)
- [x] 1.2 Do not mutate `Prepare` or CAPI routing except as needed for that hash

## 2. Connection and bouncer

- [x] 2.1 Keep the live map on `CrowdsecConnection`; add `DecisionScopeHeaders()` getter
- [x] 2.2 Remove `decisionScopeHeaders` from `Bouncer`; call `RequestScopeValues(conn.DecisionScopeHeaders(), req)`
- [x] 2.3 Do not file-split `connection.go`

## 3. Tests and usage

- [x] 3.1 `plugin_test.go`: two `New()` with the same LAPI host and different maps MUST NOT `SameConnection`; same map still shares
- [x] 3.2 Update `knowledge/devdocs/core_plugin_decisionscope.md` and `core_plugin_middleware.md` so the map is on identity, not duplicated on Bouncer
