# Code review — Standards

## Findings

### S1 — Test cleanup helper exported for integration tests
Status: completed
Argument: `ResetSharedLogFilesForTest` is documented test-only; keeps Windows pkg/logger tests able to release temp files.
