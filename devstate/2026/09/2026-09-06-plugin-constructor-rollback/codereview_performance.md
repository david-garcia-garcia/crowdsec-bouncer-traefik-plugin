# Code review — Performance
IssueKey: 2026-09-06-plugin-constructor-rollback

## Findings

### PF1 — Orphan ticker prevention
Status: completed
Argument: Immediate cancel on failed New stops stray stream/metrics tickers; no extra overhead on success path beyond one WithCancel.
