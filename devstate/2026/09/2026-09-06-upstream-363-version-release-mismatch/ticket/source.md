# Upstream #363 and #322 — version mismatch in release tags

Bound action: `add-tests` (one PR covering both upstream issues).

## Upstream #363

Title: [BUG] version still shows 1.6.0 in release v1.7.0
URL: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/363
State: CLOSED

As in issue #322 after updating to v1.7.0, "cscli bouncers list" still shows 1.6.0 as version.
Expected: Correct version number 1.7.0 should be shown.
OS: Docker; Traefik 3.7.9; Plugin v1.7.0.
Reproduce: Update to v1.7.0; check version with "cscli bouncers list".

## Upstream #322

Title: [BUG] version still shows 1.5.0 in release v1.6.0
URL: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/322
State: CLOSED

after updating to v1.6.0 "cscli bouncers list" still shows 1.5.0 for version.
Expected: should show 1.6.0
OS: Docker; Traefik 3.6.14; Plugin v1.6.0.
Reproduce: update to v1.6.0; check version with "cscli bouncers list".
