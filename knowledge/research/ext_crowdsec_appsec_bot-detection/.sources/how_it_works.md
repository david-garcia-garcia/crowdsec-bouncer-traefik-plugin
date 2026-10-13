---
url: https://docs.crowdsec.net/docs/next/appsec/bot_detection/how_it_works.md
title: How it works
fetched: 2026-09-05
authority: official
---

Request with no valid __crowdsec_challenge cookie on a protected route triggers SendChallenge.

Browser loads fpscanner (unobfuscated), PoW/crypto bundle, per-epoch signing-key module (last two obfuscated). Collects fingerprint, solves PoW, POSTs to /crowdsec-internal/challenge/submit.

On acceptance: sealed success cookie with fingerprint + expiry. Later requests present the cookie and pass without re-challenge. Cookies disabled → explicit error, not an infinite challenge loop.

Known bots: appsec-bot-challenge-exclude-* configs MatchKnownBot() then ExemptFromChallenge(reason); skipped, no cookie minted.

Challenge runtime is lazy: spins up if a loaded hook references SendChallenge(), GrantChallengeCookie(), or RejectSubmission(). Installing the bot-detection collection turns it on.
