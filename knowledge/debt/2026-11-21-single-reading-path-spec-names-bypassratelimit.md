# Name `bypassRateLimit` in the single-reading path requirement

IssueKey: 2026-11-20-add-redis-rate-limit-leg
Size: large
Action: note

## Why this follow-up
The live requirement "Action-rule skips need a single-reading path" (`openspec/specs/core_plugin_middleware_bouncer/spec.md`) lists `bypass`, `bypassLapi`, `bypassAppsec`, and `bypassModsec` as the skips a `path` row drops on a path with more than one reading. The code also drops `bypassRateLimit` there (`pkg/httprule/action.go`, `skipsLeg` covers the rate limit), and "Action rules fold every matching row" now says so. The two requirements disagree on which skips the rule covers.

## Why it was not taken
The archive phase lands only the change's deltas. This requirement was not in the change's MODIFIED set, so changing it needs its own delta.

## Risks
A reader of the single-reading requirement alone could conclude a `path` row's `bypassRateLimit` still applies on an ambiguous path, and write a test or a change on that basis.

## Context
Also update the matching sentence in "bypassCaptcha lets a request through where a captcha would be served", which lists the same skips.
