## Context

See proposal.md — Why. `master` owns AppSec HTTP on `CrowdsecConnection.AppsecQuery` (error on any non-200) and bans in `Bouncer.handleNextServeHTTP`. Upstream PR 343 parsed JSON and wrote the client response in the root `bouncer.go`. This fork must split parse (connection) from write (bouncer). Client IP is already owned by `pkg/ip.GetRemoteIP`. Real e2e CrowdSec is `v1.7.8` / CRS-only today.

## Goals / Non-Goals

**Goals:**
- Relay structured AppSec actions other than allow/ban (challenge).
- Keep legacy empty 403 as a ban and structured `ban` on `banTemplate`.
- Unit, mock, and real e2e (CrowdSec 1.8 + challenge path).

**Non-Goals:**
- New plugin config key.
- LAPI captcha (`pkg/captcha`).
- Merging upstream PR 343 as a blob (wrong package layout).
- Commenting on maxlerebourg#389.

## Decisions

1. **Parse on `CrowdsecConnection`, write on `Bouncer`.** `AppsecQuery` returns `(*AppsecResponse, error)`. Alternative: parse in bouncer — rejected; the connection already owns the AppSec round-trip and drain.

2. **Action dispatch:** empty/`allow` → `next`; `ban` → `handleBanServeHTTP`; else relay. Alternative: relay every non-allow including ban (first PR 343 patch) — rejected; review required keeping `banTemplate`.

3. **No new config.** Alternative: `crowdsecAppsecChallengeEnabled` — rejected; PR 343 and CrowdSec docs treat bouncer support as “AppSec on + challenge path routed”.

4. **Identity:** `GetRemoteIP` only. Do not read `__crowdsec_challenge` to pick an IP.

5. **Body cap 1 MiB**; oversized 200 passes, oversized non-200 errors (PR 343 tests). Clamp `http_status` to 100–999.

6. **Real e2e image `crowdsecurity/crowdsec:v1.8.0`.** Challenge router `PathPrefix(/crowdsec-internal/challenge)` + same middleware + backend `:7422`. Keep CRS `/appsec`. Mocklapi grows a JSON challenge URI so CI does not depend on hub download for the protocol.

7. **Yaegi:** keep `CreateConfig`/`New` on the module root. New types live under `pkg/crowdsecconnection` and `pkg/bouncer`.

## Risks / Trade-offs

- [Hub collection name / image] → 1.8.0 is assumed; if `appsec-bot-*` is unpublished, pin the documented 1.8 collection name during implement.
- [Challenge backend `:7422`] → after `allow`, Traefik still proxies the callback to AppSec; if the engine only needs the bouncer metadata headers, a whoami backend would 404 the JS — keep 7422.
- [Trusted AppSec `user_headers`] → AppSec is a trusted hop; still drop hop-by-hop names if we copy headers (`Connection`, `Transfer-Encoding`).
- [Metrics] → challenge increments `blockedRequests` (same as ban).

## Migration Plan

Plugin version bump. Operators enable bot-detection on CrowdSec and route `/crowdsec-internal/challenge` through the same middleware. No new Traefik key. Rollback: previous tag restores silent 403 on non-200 AppSec.
