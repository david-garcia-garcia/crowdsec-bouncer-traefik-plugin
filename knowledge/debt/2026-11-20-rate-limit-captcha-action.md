# Add the `captcha` action to rate-limit buckets

IssueKey: 2026-11-20-add-redis-rate-limit-leg
Size: large
Action: note

## Why this follow-up

The requested bucket actions are `deny`, `captcha`, and `log`. The first slice ships `deny` and `log`.

## Why it was not taken

The serving seam exists (`handleCaptchaKindServeHTTP`), but it lets a client with a valid gate cookie through. An over-limit bucket with `action: captcha` would then stop limiting every client that has solved a captcha for the gate lifetime, including a bot that solved one. Whether that exemption is wanted is the requirement's open decision 2, which the human did not answer. It also has to settle how `bypassCaptcha` rules interact with a rate-limit captcha.

## Risks

Operators who want a softer response than 429 for bursty humans have none until this lands.

## Context

Owner when taken: `pkg/bouncer/bouncer_serve_captcha.go` (`handleCaptchaKindServeHTTP`, `bypassesCaptcha`). Header would be `captcha:ratelimit:<bucket>`; metrics remediation `captcha`.
