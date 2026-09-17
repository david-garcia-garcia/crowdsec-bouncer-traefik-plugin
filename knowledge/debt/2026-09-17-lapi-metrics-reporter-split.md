# Split MetricsReporter from LAPI Client

IssueKey: 2026-09-17-lapi-transport-router-policy
Size: large
Action: note

## Why this follow-up
Target architecture treats metrics reporting as cursor-identified reclaim separate from HTTP transport and bouncer policy.

## Why it was not taken
Metrics paths share `Client` today; extracting a reporter is a separate reclaim story after transport and policy moves.

## Risks
Metrics lifecycle stays tied to full client reclaim until split.

## Context
Target table in ticket: `MetricsReporter` reclaim identity vs `Bouncer` per reload.
