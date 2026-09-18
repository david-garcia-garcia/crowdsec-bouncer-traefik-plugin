## ADDED Requirements

### Requirement: Redis password file resolved only when Redis is enabled
`ValidateParams` SHALL resolve `RedisCachePassword` and `RedisCachePasswordFile` only when `redisCacheEnabled` is true. When `redisCacheEnabled` is false, a missing, directory, or unreadable `redisCachePasswordFile` MUST NOT fail startup. When `redisCacheEnabled` is true, a non-empty `redisCachePasswordFile` that is missing, a directory, or unreadable SHALL fail startup. An empty password with an empty file path SHALL still be accepted when Redis is enabled.

#### Scenario: Disabled Redis ignores a missing password file
- **WHEN** `redisCacheEnabled` is false and `redisCachePasswordFile` names a path that does not exist
- **THEN** `ValidateParams` returns no error

#### Scenario: Disabled Redis ignores a stale password file
- **WHEN** `redisCacheEnabled` is false and `redisCachePasswordFile` names a directory or an unreadable path
- **THEN** `ValidateParams` returns no error

#### Scenario: Enabled Redis still rejects a missing password file
- **WHEN** `redisCacheEnabled` is true and `redisCachePasswordFile` names a path that does not exist
- **THEN** `ValidateParams` returns an error

#### Scenario: Enabled Redis accepts an empty password with no file
- **WHEN** `redisCacheEnabled` is true, `redisCachePassword` is empty, and `redisCachePasswordFile` is empty
- **THEN** `ValidateParams` returns no error
