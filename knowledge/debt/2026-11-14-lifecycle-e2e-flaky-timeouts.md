# Lifecycle Pester e2e fails on ~20 s timeouts with unchanged product code

IssueKey: 2026-11-14-appsec-captcha-verdict
Size: large
Action: note

## Why this follow-up
`e2e (docker + pester / lifecycle)` (`tests/e2e/real/instance_severance.Tests.ps1`) failed twice and passed once on PR #206 with the same product code: first only `R2 host change publishes a new empty client`, then ten tests (`F3`, `F1`, `N2`, `R1`–`R5`, `L4`, `T5`), each after about 20 s. Those tests route LAPI-only middlewares that never reach the changed AppSec code. A red job that clears on rerun hides real regressions and costs a rerun per PR.

## Why it was not taken
Outside this change's scope, and the job logs are not readable without signing in to GitHub, so the cause is not measured. The tests reload Traefik's file provider through `docker cp` / `touch` and wait with fixed timeouts; several PRs were running CI in parallel at the time.

## Risks
Reviewers learn to rerun red lifecycle jobs and miss a genuine failure in reclaim, late bind, or file-provider reload.

## Context
Failing runs: actions runs 43632284466 and 43633043340. Passing rerun: 43634506199. Same day, PR #208's lifecycle job passed.
