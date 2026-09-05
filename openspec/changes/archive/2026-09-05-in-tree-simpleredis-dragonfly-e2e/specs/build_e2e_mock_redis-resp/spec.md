## Purpose

The mock e2e Redis stand-in speaks the same RESP the in-tree SimpleRedis client sends, so the binary mock Redis scenario still exercises the plugin cache path.

## Requirements

### Requirement: Mock Redis parses RESP arrays
`tests/e2e/mock/mocklapi` Redis stand-in SHALL parse RESP array commands (`*<n>` then bulk strings). It SHALL still accept inline `GET ` lines. Replica mode SHALL still map `1.2.3.4` to not-banned and `1.2.3.5` to banned; primary mode SHALL miss every GET.

#### Scenario: RESP GET of the banned fixture is blocked
- **WHEN** the mock Redis scenario runs against the in-tree client (RESP GET)
- **THEN** `X-Forwarded-For: 1.2.3.5` is forbidden after the replica is selected, and `1.2.3.4` is allowed

#### Scenario: Inline GET still works
- **WHEN** a client sends an inline `GET <key>` line
- **THEN** the stand-in answers with the same miss/hit mapping as for RESP GET
