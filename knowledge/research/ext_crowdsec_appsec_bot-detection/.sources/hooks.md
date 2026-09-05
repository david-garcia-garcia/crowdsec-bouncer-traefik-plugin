---
url: https://docs.crowdsec.net/docs/next/appsec/bot_detection/hooks.md
title: Hooks reference
fetched: 2026-09-05
authority: official
---

on_challenge_submit fires on POST /crowdsec-internal/challenge/submit after crypto validation, before success cookie. Default: accept (grant cookie) on valid submission.

GrantChallengeCookie(reason, ttl?): in on_challenge_submit, issue cookie inline on the submit response (no 307). Optional ttl Go duration overrides cookie_ttl.

RejectSubmission(reason): refuse cookie despite valid crypto. Terminal with GrantChallengeCookie.

ExemptFromChallenge(reason): current request only, no cookie. SendChallenge becomes a no-op. reason labels logs and cs_appsec_challenge_exempt_total.

GrantChallengeCookie vs ExemptFromChallenge:
- Exempt: this request, no cookie — known bots, well-known paths, probes that cannot hold cookies.
- Grant: persists until cookie expires — trusted UA / internal probes for a session.

on_challenge fires on in-band requests that already carry a valid __crowdsec_challenge cookie.

fingerprint.Allowlisted true if cookie minted via GrantChallengeCookie rather than a real submission.
