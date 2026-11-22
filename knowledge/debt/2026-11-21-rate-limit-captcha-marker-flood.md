# Bound the rate-limit exemption for captcha-page traffic

IssueKey: 2026-11-20-add-redis-rate-limit-leg
Size: large
Action: note

## Why this follow-up
Human decision 5 of round 2 says the captcha page's own requests are never counted or blocked by any rate-limit bucket. Change `share-rate-limit-leg-and-bucket-actions` recognises them on a router with a usable captcha by the custom-provider widget asset paths (`captcha.Client.IsCustomResourceRequest`) and by the challenge-form marker `crowdsec_captcha_challenge=v1` (`captcha.Client.HasChallengeMarker`). Since 2026-11-22 (human decision "Cobrarlo", e4e19906) the marker skips the buckets only on a POST that this router's captcha gate answers (usable captcha, a policy with a captcha answer, no `bypassCaptcha` rule); any other marker request is charged. A client that keeps posting the marker on such a router, or only fetches widget assets, is still never charged, and each marker POST costs one call to the captcha provider's siteverify.

## Why it was not taken
The exemption is the human's decision for this round. A bound on it (for example a dedicated bucket or a cap for marker POSTs, or charging marker POSTs that fail verification) is new behaviour nobody asked for yet.

## Risks
A scripted client can flood siteverify through a router with captcha buckets while staying under every bucket. The provider's own quota or rate limit then becomes the limit, and a provider error answers the captcha as a downgrade.

## Context
Request step: `pkg/bouncer/bouncer_serve_ratelimit.go` (`serveRateLimit`, the captcha-traffic skip before `Charge`). Spec: `core_plugin_ratelimit_buckets` "The captcha page's own requests are not charged". Requirement tension: `devstate` round-2 `## Tensions`, first row.
