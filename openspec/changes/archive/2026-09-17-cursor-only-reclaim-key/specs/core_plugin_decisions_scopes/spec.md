## MODIFIED Requirements

### Requirement: Stream asks LAPI for mapped scopes
The LAPI stream request SHALL include `scopes=ip,range` plus every header scope in the Client live-router union owned by `core_plugin_lapi_scope-union`. This leaf MUST NOT compute `scopes=` from the first constructor’s write-once `decisionScopeHeaders` alone. The CAPI (alone) stream SHALL NOT add a `scopes` query parameter. Live and none SHALL keep `v1/decisions?ip=<clientIP>` and SHALL add `scope` and `value` when a mapped header is present and usable.

#### Scenario: Unmapped Country is not streamed
- **WHEN** every live holder’s `decisionScopeHeaders` is empty
- **THEN** the stream query does not include `country`

#### Scenario: Union includes a joiner’s Country map
- **WHEN** the first live stream router has an empty header map and a later live router on the same Client maps `Country`
- **THEN** a later stream query includes `country`
