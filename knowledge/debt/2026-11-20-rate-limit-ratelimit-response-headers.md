# Send `RateLimit-*` headers on rate-limit responses

IssueKey: 2026-11-20-add-redis-rate-limit-leg
Size: large
Action: note

## Why this follow-up

The requirement asks `rateLimitResponseHeaders` to send `Retry-After` "(+ RateLimit-* headers)". This change sends `Retry-After` only.

## Why it was not taken

The `RateLimit-*` fields are an IETF draft whose header names and syntax have changed between revisions (`RateLimit-Limit` / `-Remaining` / `-Reset` versus `RateLimit` plus `RateLimit-Policy`). Picking one is a product choice nobody made. Since utilities v1.0.10, `windowcounter.Take` returns a `Status` with `Limit`, `Remaining`, `Reset`, and `RetryAfter` (`ratelimit.Status` in this repo), so the values exist; in buffered mode `Remaining` is this replica's view and can still disagree with another replica's next verdict. The header shape is the open choice.

## Risks

Clients that read `RateLimit-*` instead of `Retry-After` get no hint until this lands.

## Context

Owner when taken: `pkg/bouncer/bouncer_serve_ratelimit.go` (deny writer) and `pkg/ratelimit` `Verdict`.
