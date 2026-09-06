# upstream#339

- title: [FEATURE] Add pass through for captcha-pending IPs requesting custom captcha resources
- state: OPEN
- url: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/339
- created: 2026-06-17T14:34:01Z
- updated: 2026-07-01T19:33:03Z
- labels: (none)

## Body

**Is your feature request related to a problem? Please describe.** 🐛
When using a custom captcha like wicketkeeper and an IP is captcha-flagged, it is not able by default to request the necessary resources to complete the captcha (/fast.js and /v0/challenge). Instead it is prompted with another captcha challenge html.

**Describe the solution you'd like** ✨
1. A new CaptchaCustomChallengeURL configuration option should be added for /v0/challenge.
2. Captcha-flagged IPs should be passed through to CaptchaCustomJsURL and CaptchaCustomChallengeURL. Banned IPs should still not be passed through.
