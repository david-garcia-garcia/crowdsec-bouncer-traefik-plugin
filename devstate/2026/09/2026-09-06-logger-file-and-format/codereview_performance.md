# Code review — Performance

## Findings

None. `sync.Map` lookup is O(1) amortized; one map entry per distinct log path.
