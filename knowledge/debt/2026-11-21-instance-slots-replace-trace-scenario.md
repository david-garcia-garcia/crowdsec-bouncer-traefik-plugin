# Align the instance-slots "Replace A by B" trace scenario with the code

IssueKey: 2026-11-20-add-redis-rate-limit-leg
Size: large
Action: note

## Why this follow-up
The live scenario "Replace A by B logs two bound lines" under "Lifecycle logs match e2e grep contract" (`openspec/specs/core_plugin_middleware_instance-slots/spec.md`) says a subscriber logs bound for A then bound for B "without an unbound between them". The code logs `crowdsec bouncer unbound` with A's incarnation before `crowdsec bouncer bound` for B (`pkg/bouncer/bouncer_leg_*.go`, `receive<Leg>`: `previous != nil && previous != current`). No test asserts either order; the real-stack severance suite greps only for `crowdsec bouncer bound`.

## Why it was not taken
Change `share-rate-limit-leg-and-bucket-actions` extracts the leg binding without changing observable behaviour, and its new trace test pins today's code. Rewriting the scenario, or changing the trace, is a separate decision about which order is the contract.

## Risks
A later change that follows the scenario text would drop the unbound line that operators may already grep for, or a reviewer would flag the pinned order as a spec violation.
