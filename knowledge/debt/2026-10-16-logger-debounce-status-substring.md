# Tighten Debounced status-code assertion

IssueKey: 2026-10-16-captcha-leftover-form-marker
Size: small
Action: note

## Why this follow-up
`TestDebounced_sameMessageOnce` treats any `502` substring as a leaked second statusCode, so a log timestamp whose milliseconds are `.502` fails the test.

## Why it was not taken
The flake is in `pkg/logger`, outside this change's leftover-form marker work. Unattended take is only small rows on files this run created.

## Risks
`go test ./pkg/...` can fail on the wall clock even when debounce behavior is correct.
