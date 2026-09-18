# Rename `GetVariable` to name file-then-field lookup

IssueKey: 2026-09-18-captcha-empty-keys-accepted
Size: large
Action: note

## Why this follow-up
`GetVariable` hides that lookup is the `*File` field then the config field, and that it does not read the environment.

## Why it was not taken
Many `ValidateParams` call sites. Unattended take is only small rows on files this run created.

## Risks
Later tickets keep saying “file/env lookup” because the name does not name the sources.

## Context
Current: `pkg/configuration/configuration.go` `GetVariable`
Proposed: a name that says file-then-field (no env)
