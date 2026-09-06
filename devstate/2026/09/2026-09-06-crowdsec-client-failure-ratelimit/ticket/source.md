# Backoff LAPI and AppSec when CrowdSec is down or slow

AppSec, live, and none modes talk to CrowdSec on the request critical path.

If CrowdSec degrades, cannot keep up, or is down, even though we have fail-open / fail-close knobs (ban, captcha, passthrough), the experience is still degraded substantially when the service is down or slow.

We need to back off temporarily from using any of those services if we detect that they are misbehaving, and restore them when they become available again.

Reference implementation: https://github.com/david-garcia-garcia/traefik-modsecurity/tree/main/pkg/health

Rate-limiter background: https://dev.to/jones_charles_ad50858dbc0/implementing-rate-limiters-in-go-token-bucket-and-leaky-bucket-made-simple-5162

A leaky-bucket implementation is acceptable instead of a sliding-window bucket, given strong test coverage of that package. Adjust the config knobs to match the chosen failure-rate-limiting solution.

Proposed knobs (window-threshold shape; rename if the limiter changes):

- `lapiFailureBackoffTimeout`
- `lapiFailureBackoffBucketWindow`
- `lapiFailureBackoffBucketThreshold`
- `appsecFailureBackoffTimeout`
- `appsecFailureBackoffBucketWindow`
- `appsecFailureBackoffBucketThreshold`

Dest branch: `master`. Done when the PR is delivered with passing CI.

IssueKey: `2026-09-06-crowdsec-client-failure-ratelimit`
