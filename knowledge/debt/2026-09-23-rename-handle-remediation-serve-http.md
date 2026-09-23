# Rename `handleRemediationServeHTTP`

IssueKey: 2026-09-23-captcha-unsubscribed-ban
Size: large
Action: note

## Why this follow-up

`handle` hides the job. The method is the captcha-kind vs ban owner on the request path, not a generic handler.

## Why it was not taken

Many production and test call sites. Unattended take is only small rows on files this run created.

## Risks

Later tickets keep adding branches to a vague name instead of naming captcha-kind serve vs ban.
