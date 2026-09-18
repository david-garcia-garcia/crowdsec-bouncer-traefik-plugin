# Retarget renovate depNameTemplate off maxlerebourg

IssueKey: 2026-09-18-fork-plugin-module-path
Size: large
Action: note

## Why this follow-up
`renovate.json` still uses `depNameTemplate: maxlerebourg/crowdsec-bouncer-traefik-plugin` (and `gitAuthor` of that org). After this tree’s Go/Traefik module identity moves to `github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin`, those templates keep pointing at upstream.

## Why it was not taken
The ticket listed renovate as out of scope. Unattended take is only small rows on files this run created.

## Risks
Renovate PRs keep targeting the old GitHub path after the fork identity change.

## Context
Current: `renovate.json` `depNameTemplate` (two entries) and `gitAuthor`.
Proposed: templates that name this repo, in a later change.
