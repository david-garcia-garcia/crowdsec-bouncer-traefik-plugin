# Narrow LAPI session key to cursor identity

IssueKey: 2026-09-17-lapi-transport-router-policy
Size: large
Action: note

## Why this follow-up
Peek/live-prefix/view reclaim APIs and first-wins scope wiring keep settings broader than pure cursor identity; ticket defers deleting peek helpers and unioning live router scopes.

## Why it was not taken
Touches `pkg/reclaim/peek.go`, upstream traefik-middleware-utilities alignment, and public reclaim behavior — out of scope for transport/router-policy split.

## Risks
Remaining peek paths may still hide mismatched joiner configuration until the key is narrowed.

## Context
Current: `pkg/reclaim/peek.go`; proposed: scopes union of live routers, real upstream reclaim import.
