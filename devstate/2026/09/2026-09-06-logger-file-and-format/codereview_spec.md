# Code review — Spec

## Findings

### SP1 — Shared file per path
Status: completed
Argument: `logOutput` + `sync.Map` satisfies spec requirement for process-lifetime reuse.

### SP2 — Case-insensitive JSON
Status: completed
Argument: `strings.EqualFold(logFormat, "json")` matches spec scenarios.
