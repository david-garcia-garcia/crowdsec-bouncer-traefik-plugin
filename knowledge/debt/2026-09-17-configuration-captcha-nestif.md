# Dest nestif on CaptchaProvider validation

IssueKey: 2026-09-17-appsec-query-hardening
Size: large
Action: note

## Why this follow-up
`golangci-lint` `nestif` fails Main Process on `pkg/configuration/configuration.go` (`if config.CaptchaProvider != ""`, complexity 6). That lint is on dest `master` and is not part of the AppSec Query apply.

## Why it was not taken
The file is outside this ticket’s AppSec surface. Unattended take is only small rows on files this run created. Other worktrees own neighboring packages.

## Risks
Every PR that runs `make lint` stays red until someone lowers that nesting on dest.
