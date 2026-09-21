## MODIFIED Requirements

### Requirement: Live routers union header scopes into stream query
Only the middleware that Opens the stream Client SHALL register `lapiScopeHeaders` on that Client. Bouncing subscribers MUST NOT register. Stream `scopes=` and the store filter still snapshot the opener's map (write-once plus that Open's ctx).

#### Scenario: Subscriber does not add scopes
- **WHEN** the opener published a stream Client with no `lapiScopeHeaders`
- **AND** a bouncing subscriber has `lapiScopeHeaders` Country
- **THEN** stream `scopes=` does not include Country from that subscriber
