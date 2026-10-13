# Delivery

## Motivation

CrowdSec AppSec bot-detection answers a suspicious page with JSON `action: challenge`, then the browser loads scripts and posts a proof under `/crowdsec-internal/challenge/`. Each of those AppSec answers was counted as a dropped request, so one solved visit looked like four blocks in the LAPI usage-metrics window.

On this fork's `main`, AppSec 403 was not parsed at all, so those answers were operator bans (empty body, still +1 each). Either way the window over-counts the challenge.

Priority: P2 — operators see inflated dropped counts for every solved bot-detection challenge

## Implementation

`appsecQuery` now parses a 403 JSON body. When `action` is `challenge`, `handleAppsecResponseServeHTTP` writes the envelope to the client. `blockedRequests` increments only when the path is not under `/crowdsec-internal/challenge/`. Other 403s still ban. The metrics POST is unchanged.

## What this changes
**Operators.** A bot-detection challenge page counts as one dropped request; scripts and submit under `/crowdsec-internal/challenge/` do not.
**Admin users.** None.
**Developers.** `appsecQuery` returns `(*AppSecResponse, error)`; a 403 with `action: challenge` is a nil error plus the envelope.
**End users.** The browser receives the AppSec challenge HTML instead of the operator ban page when AppSec returns that envelope.
