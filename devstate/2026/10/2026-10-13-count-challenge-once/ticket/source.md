# Count a bot-detection challenge once

On master, pkg/bouncer/bouncer.go handleAppsecResponseServeHTTP calls recordDropped for every relayed AppSec envelope. A visitor who solves a challenge therefore increments dropped for the page, fpscanner.js, pow-worker.js, and /crowdsec-internal/challenge/submit, including a successful submit.

The bot-detection spec currently says blockedRequests SHALL increment on relay. Update that so a relay whose path is under /crowdsec-internal/challenge/ does not increment dropped (request or bytes). The challenge page (any other path) still increments once. Bans, pkg/captcha, and non-challenge relays stay counted as today.

Do not add origin or remediation labels. Do not change the metrics POST shape.

Regression test: a challenge envelope on /protected increments dropped by 1; the same envelope on /crowdsec-internal/challenge/submit does not. Use the existing TestDroppedCount helper. Run the tests on this machine.

Out of scope: challenge-path 404, LAPI decision types, workflow files, the closed PR 195.

Upstream (must appear on the delivery card): https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 point 5. Do not copy that patch.

Constraints from the conductor:
- DestBranch is master. origin/main is the upstream mirror and is the WRONG base.
- PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/195 was closed because it targeted main and reimplemented challenge JSON parsing that master already has. Do not reopen it.
- Do NOT edit .github/workflows.
- Do NOT hardcode a maxlerebourg checkout path.
- Do NOT add a vendor GOPATH copy step.
- Do NOT add a new AppSec JSON parser; master already relays challenge envelopes in handleAppsecResponseServeHTTP.
