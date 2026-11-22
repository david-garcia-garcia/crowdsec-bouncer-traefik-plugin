## MODIFIED Requirements

### Requirement: Rate-limit drops use plugin origins
When a LAPI client is bound to the router that charged the request, a rate-limit bucket that answers SHALL count one drop (request and byte series) with origin `plugin:ratelimit:<bucket name>` and the client's IP type: remediation `ban` for a `ratelimit` answer, including a `captcha` bucket answered as `ratelimit` (a `bypassCaptcha` rule or no usable captcha), and remediation `captcha` when a `captcha` bucket serves the challenge page. A challenge-form POST that the rate-limit step hands to the captcha gate SHALL count one drop with origin `plugin:ratelimit` (no bucket answered) and remediation `captcha` when the client holds no valid gate cookie (the challenge page again, or the solved redirect after a valid answer), as the captcha writer records every leg's form answer. A rate-limit failure action `ban` or `captcha` SHALL count one drop with origin `plugin:ratelimit_failure` and remediation `ban` or `captcha` as served (a captcha downgraded to a ban counts as `ban`). A `log` bucket over its limit, a `bypassRateLimit` skip, a widget asset that continues as the captcha page's own traffic, a client whose valid captcha gate lets it through, failure action `passthrough`, a missing rate-limit client, and a request that a `bypassCaptcha` rule let through on the failure action SHALL NOT count a drop. When no LAPI client is bound, nothing SHALL be counted, as for action-rule drops.

#### Scenario: Deny drop uses the bucket origin
- **WHEN** `ratelimit` bucket `login` answers an IPv4 client on a router with a bound LAPI client
- **THEN** usage metrics count one `dropped` with origin `plugin:ratelimit:login`, remediation `ban`, and ip type `ipv4`

#### Scenario: Failure-action ban uses the failure origin
- **WHEN** the rate-limit counter returns an error and `rateLimitFailureAction` is `ban`
- **THEN** usage metrics count one `dropped` with origin `plugin:ratelimit_failure` and remediation `ban`

#### Scenario: Log bucket is not a drop
- **WHEN** only a `log` bucket is over its limit
- **THEN** usage-metrics `dropped` is not incremented
- **AND** `processed` is incremented once

#### Scenario: Captcha bucket challenge is a captcha drop
- **WHEN** `captcha` bucket `per-ip-soft` serves the challenge page on a router with a bound LAPI client
- **THEN** usage metrics count one `dropped` with origin `plugin:ratelimit:per-ip-soft` and remediation `captcha`

#### Scenario: Captcha bucket answered as a rate limit is a ban drop
- **WHEN** `captcha` bucket `per-ip-soft` answers as `ratelimit` because a `bypassCaptcha` rule matched
- **THEN** usage metrics count one `dropped` with origin `plugin:ratelimit:per-ip-soft` and remediation `ban`
