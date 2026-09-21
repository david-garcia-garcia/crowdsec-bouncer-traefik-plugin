# Requirement
IssueKey: 2026-09-18-improve-readme

## Problem
The plugin README is the operator and user surface for this CrowdSec Traefik bouncer. The ticket asks to improve that document. This phase only grounds the ticket.

## Current (code)
- Repo-root `README.md` is present on dest. `README.md`
- Title, badges, AppSec/remediation/scope/mode intro, then Usage, Note, Variables, Configuration, Testing, Examples, Local Mode, About. `README.md`
- Variables is a long option list (`Enabled`, `LogLevel`, `LapiMode`, AppSec, forwarded-header, captcha, cache). `README.md`
- Configuration shows static and dynamic Traefik YAML. `README.md`
- Examples link to `examples/*/README.md`. `README.md`
- Local Mode documents Traefik `plugins-local` layout. `README.md`
- No usage packet under `knowledge/devdocs/` names this README. not found

## Desired
- Improve the plugin README for operators and users.
- Prepare does not rewrite `README.md`.

## Affected
- `README.md`

## Out of scope
- Rewriting `README.md` in this phase
- Product code, specs, and example trees unless a later phase names them
- Inventing a section-by-section rewrite list (not in the ticket)

## Unknowns
- What “improve” means (structure, accuracy, operator gaps, copy)
- Which README sections later phases may change
- Whether `examples/*/README.md` is in scope (ticket names the plugin README only)

## Tensions
- Ticket is a broad improve with no section list or acceptance bar.
- Caller fence: prepare grounds only and must not rewrite `README.md`.
