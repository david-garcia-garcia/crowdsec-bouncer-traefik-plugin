# Send `RateLimit-*` headers on rate-limit responses

IssueKey: 2026-11-20-add-redis-rate-limit-leg
Size: large
Action: note

## Why this follow-up

The requirement asks `rateLimitResponseHeaders` to send `Retry-After` "(+ RateLimit-* headers)". This change sends `Retry-After` only.

## Why it was not taken

The `RateLimit-*` fields are an IETF draft whose header names and syntax have changed between revisions (`RateLimit-Limit` / `-Remaining` / `-Reset` versus `RateLimit` plus `RateLimit-Policy`). Picking one is a product choice nobody made. `windowcounter.Take` returns a sliding-window estimate, not a remaining count, so a `Remaining` value would be derived and could disagree with the next verdict in buffered mode.

## Risks

Clients that read `RateLimit-*` instead of `Retry-After` get no hint until this lands.

## Context

Owner when taken: `pkg/bouncer/bouncer_serve_ratelimit.go` (deny writer) and `pkg/ratelimit` `Verdict`.
