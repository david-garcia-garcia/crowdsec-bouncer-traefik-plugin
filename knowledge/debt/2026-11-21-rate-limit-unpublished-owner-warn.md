# Warn when a rate-limit subscriber serves with no published owner

IssueKey: 2026-11-20-add-redis-rate-limit-leg
Size: large
Action: note

## Why this follow-up
A router whose `rateLimitInstanceName` no owner publishes lets every request through; the only sign is the TRACE `crowdsec bouncer unbound` line at bind. A typo in the instance name or a removed owner silently turns the limit off (round-2 code review, Security 2). The other legs apply a failure action, and an unsubscribed or unusable captcha logs WARN or ERROR.

## Why it was not taken
The passthrough is the documented contract (spec `core_plugin_ratelimit_client` "Missing rate-limit client charges nothing", README "When the policy is not loaded"). A request-time WARN (for example through `logger.Debounced`, as `logRateLimitCaptchaDowngrade` does) is new behaviour nobody asked for.

## Risks
An operator believes a route is rate limited while it is not, until they raise the log level to TRACE.
