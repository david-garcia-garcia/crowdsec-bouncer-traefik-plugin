# Count a bot-detection challenge once

`handleAppsecResponseServeHTTP` calls `recordDropped` for every relayed AppSec envelope. A visitor who solves a challenge therefore increments dropped for the page, `fpscanner.js`, `pow-worker.js`, and `/crowdsec-internal/challenge/submit`, including a successful submit. A throwaway test on this tree: the page counted 1, then the submit path counted +1 (`TestDroppedCount` origin `appsec`, remediation empty).

The bot-detection spec currently says `blockedRequests` SHALL increment on relay. Update that so a relay whose path is under `/crowdsec-internal/challenge/` does not increment dropped (request or bytes). The challenge page (any other path) still increments once. Bans, captcha remediation via pkg/captcha, and non-challenge relays stay counted as today.

Do not add origin or remediation labels. Do not change the metrics POST shape.

Regression test: a challenge envelope on `/protected` increments dropped by 1; the same envelope on `/crowdsec-internal/challenge/submit` does not. Run the tests on this machine.

Upstream (must appear on every delivery card / PR body): https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 (fixes https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/402, point 5). Say this fork's gap versus that PR. Do not claim we copied their patch.
