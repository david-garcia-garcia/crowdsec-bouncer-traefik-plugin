## ADDED Requirements

### Requirement: Rate-limit drops use plugin origins
When a LAPI client is bound to the router, a rate-limit `deny` SHALL count one drop (request and byte series) with origin `plugin:ratelimit:<bucket name>`, remediation `ban`, and the client's IP type. A rate-limit failure action `ban` or `captcha` SHALL count one drop with origin `plugin:ratelimit_failure` and remediation `ban` or `captcha` as served (a captcha downgraded to a ban counts as `ban`). A `log` bucket over its limit, a `bypassRateLimit` skip, failure action `passthrough`, and a request that a `bypassCaptcha` rule let through SHALL NOT count a drop. When no LAPI client is bound, nothing SHALL be counted, as for action-rule drops.

#### Scenario: Deny drop uses the bucket origin
- **WHEN** bucket `login` denies an IPv4 client on a router with a bound LAPI client
- **THEN** usage metrics count one `dropped` with origin `plugin:ratelimit:login`, remediation `ban`, and ip type `ipv4`

#### Scenario: Failure-action ban uses the failure origin
- **WHEN** the rate-limit counter returns an error and `rateLimitFailureAction` is `ban`
- **THEN** usage metrics count one `dropped` with origin `plugin:ratelimit_failure` and remediation `ban`

#### Scenario: Log bucket is not a drop
- **WHEN** only a `log` bucket is over its limit
- **THEN** usage-metrics `dropped` is not incremented
- **AND** `processed` is incremented once
