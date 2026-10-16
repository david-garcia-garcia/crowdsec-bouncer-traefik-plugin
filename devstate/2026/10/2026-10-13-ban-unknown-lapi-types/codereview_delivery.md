# Delivery

## Motivation
A LAPI or blocklist decision whose type is neither ban nor captcha is skipped at ingest. Stream Put, Range upsert, and live/none query then treat the client as clean. Type challenge is the CrowdSec case that carries nothing to render; type allow and any other unknown type take the same skip. lua-cs-bouncer fails those types closed to ban. Leaving the skip in place lets an IP with an active unknown decision through.

Priority: P1 — unknown LAPI types fail open today

## Implementation
LAPI ingest maps ban and captcha through RemediationValue and stores every other type as ban, TRACE-logging handleStreamCache:unknownType via logger.Trace. streamPutItem, Range upsert, strongestLiveDecision, and queryLiveDecisions share that helper. RemediationValue stays empty so origin remap still treats empty as not a code. Same job as upstream https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 point 1; this fork applies it at LAPI ingest because master has no root bouncer.go.

## What this changes
**Operators.** Unknown LAPI decision types (challenge, allow, anything else) now ban instead of allowing the IP. The unknown-type log is TRACE, not Info.
**Admin users.** None.
**Developers.** LAPI ingest stores unknown types as ban; RemediationValue still returns empty for those types.
**End users.** A client with only an unknown-type LAPI decision is banned instead of allowed.
