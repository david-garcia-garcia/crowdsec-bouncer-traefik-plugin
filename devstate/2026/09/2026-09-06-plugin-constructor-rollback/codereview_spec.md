# Code review — Spec
IssueKey: 2026-09-06-plugin-constructor-rollback

## Findings

### SP1 — Constructor rollback requirement
Status: completed
Argument: bindCtx cancel on error satisfies rollback scenario; tests assert holder release after AppSec TLS failure.

### SP2 — Appsec mode guard
Status: completed
Argument: plugin.go rejects appsec without enabled; test covers rejection path.
