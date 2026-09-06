## ADDED Requirements

### Requirement: Set returns write errors
`cache.Client.Set` SHALL return an error when the underlying Redis writer fails. In-memory cache `Set` SHALL return nil. Callers that ignore the return value SHALL behave as today except that errors are no longer swallowed inside the cache layer.

#### Scenario: Redis set failure is observable
- **WHEN** Redis is enabled and the writer returns an error on SET
- **THEN** `Client.Set` returns a non-nil error

#### Scenario: Memory set always succeeds
- **WHEN** Redis is disabled and `Client.Set` is called
- **THEN** `Client.Set` returns nil
