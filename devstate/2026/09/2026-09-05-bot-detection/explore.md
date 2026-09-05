# Explore
IssueKey: 2026-09-05-bot-detection

## Concepts

**Structured AppSec response**:
CrowdSec 1.8 AppSec can return a JSON body with `action`, `http_status`, `user_body_content`, `user_cookies`, `user_headers` instead of an empty 403. The bouncer must parse it and either pass, ban, or write that payload to the client. Source: upstream PR 343. Not in this tree today.

**Challenge**:
A non-allow, non-ban `action` (PR 343 uses `"challenge"`) that carries fingerprint HTML and a `__crowdsec_challenge` cookie. The browser then calls `/crowdsec-internal/challenge/*`. That path must hit the same plugin middleware so AppSec sees the solve. Distinct from LAPI captcha (`pkg/captcha`).

**Legacy AppSec 403**:
Empty or non-JSON non-200 from AppSec. Today's `AppsecQuery` error → `handleBanServeHTTP`. Keep this for CRS-inband and old engines.

**Client address**:
`pkg/ip.GetRemoteIP` already owns the address `ServeHTTP` passes into `AppsecQuery` as `X-Crowdsec-Appsec-Ip`. Do not parse `RemoteAddr` on the AppSec path.

```
  client ──► Traefik ──► Bouncer.ServeHTTP
                              │
                              ├─ GetRemoteIP (owner)
                              ├─ LAPI/cache remediation?
                              └─ handleNextServeHTTP
                                    │
                                    ├─ AppsecQuery ──► CrowdSec :7422
                                    │     200 / allow     → next
                                    │     parse error + non-200 → ban
                                    │     action=ban      → banTemplate
                                    │     action=challenge → write status/headers/cookies/body
                                    └─ next.ServeHTTP (backend or challenge service)
```

## Decisions

- Parse JSON on `CrowdsecConnection.AppsecQuery` (it already owns the AppSec HTTP round-trip). Return `(*AppsecResponse, error)`. Keep the name `Appsec*` to match `AppsecPolicy`.
- Write to the client on `Bouncer` (it already owns `ResponseWriter`, `banTemplate`, remediation header). Do not let `crowdsecconnection` write HTTP.
- No new plugin config key. Enable with existing `crowdsecAppsecEnabled`.
- `action` empty or `allow` → `next`. `action` `ban` → existing `handleBanServeHTTP` (keep operator `banTemplate`). Any other non-allow action → relay AppSec status/headers/cookies/body.
- Clamp `http_status` to 100–999; else `remediationStatusCode`. If AppSec omits `Content-Type`, use `banTemplateContentType`.
- Cap AppSec response body at 1 MiB (PR 343). Keep draining so idle connections reuse (`appsec_test.go`).
- Unit tests in `pkg/crowdsecconnection` (parse, oversized OK vs 403) and `pkg/bouncer` (relay challenge, legacy 403, structured ban keeps template).
- Mock e2e: extend `mocklapi` AppSec to return structured JSON for a dedicated URI (and keep empty 403 for existing probes).
- Real e2e: bump the test CrowdSec image to `v1.8.0`, load `crowdsecurity/appsec-bot-*` (or the published hub equivalent), keep CRS inband on `/appsec`, add a bot-detection route plus `PathPrefix(/crowdsec-internal/challenge)` through the same AppSec middleware. Backend for the challenge prefix is AppSec `:7422` (PR 343 compose).
- Do not port PR 343's `bouncer.go` as a blob: this fork split AppSec into `pkg/crowdsecconnection`. Port the protocol, not the file layout.
- Do not comment workflow cards onto maxlerebourg#389.

## Open questions

- Q: What exact JSON fields and HTTP status does CrowdSec 1.8.0 AppSec send for challenge vs ban vs allow?
  Decision: resolved — listener 200 is allow; listener 403 carries JSON `action` / `http_status` / `user_body_content` / `user_cookies` / `user_headers`. Challenge is always listener 403 plus `action: challenge`. Browser status is `http_status` (200 page/submit, 307 grant). Missing `http_status` → 200. Empty challenge body → ban. Source: knowledge/research/ext_crowdsec_appsec_bot-detection/.
  By: implement

- Q: Does Traefik need a new plugin option for bot-detection?
  Decision: resolved — no. AppSec enabled plus challenge paths through the same middleware.
  By: implement

- Q: Who already owns the client address AppSec should see?
  Decision: resolved — `pkg/ip.GetRemoteIP` in `Bouncer.ServeHTTP`; `AppsecQuery` already receives that `ip` and sets `X-Crowdsec-Appsec-Ip`. Reuse. Do not parse `RemoteAddr` or cookies for identity.
  By: explore

- Q: How must `/crowdsec-internal/challenge` be wired in our stacks?
  Decision: resolved — Traefik router `PathPrefix(/crowdsec-internal/challenge)` with the same bouncer middleware; service load-balancer to the AppSec port so origin never sees the callback.
  By: implement

- Q: Which CrowdSec image and hub items for real e2e?
  Decision: resolved — `crowdsecurity/crowdsec:v1.8.0`, collection `crowdsecurity/appsec-bot-challenge`, acquis `crowdsecurity/appsec-bot-*` on port 7423 so CRS on 7422 stays unchallenged.
  By: implement

- Q: Should structured `action=ban` use AppSec HTML or the operator ban template?
  Decision: resolved — keep `handleBanServeHTTP` / `banTemplate`.
  By: implement

- Q: Do we increment `blockedRequests` for a challenge?
  Decision: resolved — yes, same as AppSec ban (`IncBlocked` on relay).
  By: implement

- Q: Reproduce issue 389 in this worktree?
  Decision: assumed — not reproduced live in explore; unit/mock cover the protocol; real e2e is the live reproduction.
  By: implement
