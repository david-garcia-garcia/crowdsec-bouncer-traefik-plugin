# Captcha redirects use the request URL as Location

IssueKey: 2026-11-14-appsec-captcha-verdict
Size: large
Action: note

## Why this follow-up
`pkg/captcha` answers a solved captcha (`ServeHTTP`) and a leftover challenge form (`WriteSolvedRedirect`) with `302` to `req.URL.String()`. A request path such as `//evil.com` yields `Location: //evil.com`, a scheme-relative redirect off-site, when Traefik does not collapse duplicate slashes. PR #206 lets an AppSec-allowed challenge-marker POST reach these redirects with no captcha decision on the client, which widens who can reach the sink.

## Why it was not taken
The sink is in `pkg/captcha`, outside this change's diff, and predates it. An unattended review does not apply cause fixes outside the diff. Exploiting it also needs a valid provider token on the POST (first-solve path) or the victim's own gate cookie (leftover path).

## Risks
An attacker who gets a victim to submit a solved captcha form to a crafted path could bounce the victim to another site.

## Context
Proposed fix from the Security axis: redirect to a same-origin path only (`"/" + strings.TrimLeft(req.URL.EscapedPath(), "/")` plus the raw query) in `ServeHTTP` and `WriteSolvedRedirect`, with a test for `//evil.com`.
