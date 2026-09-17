## REMOVED Requirements

### Requirement: Mock Redis parses RESP arrays
**Reason**: Plugin cache no longer uses Redis/RESP; mock Redis scenario is retired with the backend.
**Migration**: Rely on in-memory cache unit tests and remaining e2e routes without Redis stand-in.
