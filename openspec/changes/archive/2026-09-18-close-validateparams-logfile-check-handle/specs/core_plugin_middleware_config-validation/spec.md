## ADDED Requirements

### Requirement: Writable log path check does not retain its descriptor
When `LogFilePath` is non-empty, `ValidateParams` SHALL still reject an unwritable path. After a successful writability check it MUST NOT retain a file descriptor that exists only for that check. It MUST still perform the check even when a process-lifetime logger file is already open for the same path.

#### Scenario: Successful writable path leaves no check descriptor
- **WHEN** `ValidateParams` succeeds with a non-empty writable `LogFilePath` and no process-lifetime logger file is held for that path
- **THEN** the process has no open descriptor that names that path

#### Scenario: Unwritable path still fails
- **WHEN** `LogFilePath` is non-empty and not writable
- **THEN** `ValidateParams` returns an error
