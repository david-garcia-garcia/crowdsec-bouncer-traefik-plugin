# Charge a challenge-marker POST that no captcha gate answers

IssueKey: 2026-11-20-add-redis-rate-limit-leg
Size: large
Action: note

## Why this follow-up
On a router with a usable captcha, `serveRateLimit` skips every bucket for any POST that carries the challenge marker `crowdsec_captcha_challenge=v1`, then hands it to the captcha gate only when the bound policy can answer with a captcha and no `bypassCaptcha` rule matched. When `answerRateLimitChallengeForm` declines, the POST continues uncharged. Two reachable cases (round-2 code review, Security 1):
- A policy with only `ratelimit` buckets on a router that has a captcha (for example to serve LAPI captcha decisions) and no AppSec step: nothing after the rate-limit step validates the form, so the POST reaches the application with its body intact. Adding `&crowdsec_captcha_challenge=v1` to a form-encoded `POST /login` disables a brute-force `ratelimit` bucket on that path.
- A `bypassCaptcha` rule matching the POST: the rate-limit step and `serveAppsecCaptchaGate` both return false, so the POST reaches the application uncharged, although the README says a `bypassCaptcha` request still gets the bucket's ratelimit answer.

## Why it was not taken
Human decision 5 of round 2 exempts the captcha page's own requests from every bucket, and the spec line "Otherwise the POST SHALL continue to the AppSec step" allows this path. Charging a marker POST that no gate answers narrows that exemption, which is a product decision, not an unattended review fix.

## Risks
A client that knows the marker name bypasses brute-force or abuse buckets on any form endpoint of a router with a usable captcha and no AppSec, and on any path a `bypassCaptcha` rule covers.

## Context
Owner: `pkg/bouncer/bouncer_serve_ratelimit.go` (`serveRateLimit` marker branch, `answerRateLimitChallengeForm`). Candidate fix: skip the buckets for a marker POST only when a captcha gate on this router will answer it; otherwise charge it like any other request. Checking `rateLimitAnswersWithCaptcha` before `isCaptchaFormAnswer` would also remove the 64 KiB body peek on every POST of such routes (round-2 code review, Performance 1). Related: `knowledge/debt/2026-11-21-rate-limit-captcha-marker-flood.md` (siteverify flood while the gate does answer).
