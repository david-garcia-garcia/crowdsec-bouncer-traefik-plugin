# Challenge submit needs the full POST body

The bot-detection proof is POSTed to `/crowdsec-internal/challenge/submit`. AppSec rejects a truncated body and the visitor is challenged forever.

This fork: `appsecBodyLimit` 0 means unlimited (skip LimitReader, read the whole readable body). `Test_appsecQuery_zeroBodyLimitForwardsPost` already proves limit 0 POSTs the full payload. Re-run that test; do not change that behavior and do not add a duplicate test.

A positive limit smaller than the form still truncates, with no log that names the challenge submit. README `AppsecBodyLimit` says default 10485760 and "0 means no limit" but never says the challenge proof needs that body.

Desired: README (the AppSec / bot-detection section and the AppsecBodyLimit key) states that `/crowdsec-internal/challenge/submit` must reach AppSec with the full form, the default 10MB is enough, a smaller positive limit cuts the proof short, and 0 means no limit (the whole body is sent). Do not write that 0 sends nothing.

Out of scope: changing the limit implementation, metrics, challenge-path 404.

Upstream (must appear on every delivery card / PR body): https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 (fixes https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/402, point 6). Say this fork's gap versus that PR. Do not claim we copied their patch. Their README says body limit 0 sends no body. That is FALSE here.
