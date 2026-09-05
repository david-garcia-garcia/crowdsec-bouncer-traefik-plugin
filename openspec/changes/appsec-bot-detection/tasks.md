## 1. Connection parse

- [ ] 1.1 Change `AppsecQuery` to return `(*AppsecResponse, error)`, parse JSON, cap body at 1 MiB, keep drain and existing 500/unreachable policy
- [ ] 1.2 Unit tests: allow JSON, empty 200, oversized 200 pass, oversized 403 error, connection reuse still one conn

## 2. Bouncer relay

- [ ] 2.1 `handleNextServeHTTP` dispatches allow / ban / relay; clamp status; fallback Content-Type; increment blocked counter on relay
- [ ] 2.2 Unit tests: challenge relays status/headers/cookies/body; structured ban keeps banTemplate; empty 403 still bans; out-of-range status does not panic

## 3. Mock e2e

- [ ] 3.1 `mocklapi` AppSec returns structured challenge JSON for a dedicated URI; keep empty 403/500/502 probes
- [ ] 3.2 Scenario asserts challenge status/body/cookie and that legacy 403 still bans

## 4. Real-stack e2e

- [ ] 4.1 Pin CrowdSec `v1.8.0`; load bot-detection plus CRS; add `/crowdsec-internal/challenge` through the AppSec middleware to port 7422
- [ ] 4.2 Pester: challenge is not a silent empty 403; CRS SQLi still 403; client identity only `X-Forwarded-For`

## 5. Docs

- [ ] 5.1 README (and an example if needed): AppSec on, challenge path through the same middleware, no new plugin key
