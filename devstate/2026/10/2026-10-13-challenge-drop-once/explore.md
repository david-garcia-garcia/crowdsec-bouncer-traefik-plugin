# Explore

## Concepts

- `bouncer.go` `appsecQuery` — sends the request to AppSec; on dest, HTTP 200 is allow and any other non-500 status is `error` (ban). Body is drained, not parsed. One caller: `handleNextServeHTTP`.
- `bouncer.go` `handleNextServeHTTP` — after LAPI allow (or appsec-only mode), queries AppSec then `next` or ban.
- `bouncer.go` `handleBanServeHTTP` — operator ban page; always `atomic.AddInt64(&blockedRequests, 1)`.
- `bouncer.go` `handleRemediationServeHTTP` — LAPI captcha via `pkg/captcha`; increments `blockedRequests` when the captcha page is served.
- `bouncer.go` `reportMetrics` — POST `dropped` with labels `{type: traefik_plugin}` only. No bytes series, no origin, no remediation.
- `blockedRequests` — package `int64` window counter. Dest has no `recordDropped` / `TestDroppedCount`.
- `handleAppsecResponseServeHTTP` — not found on dest. Present on `upstream/main` after #343.

Seam: `handleNextServeHTTP` → `appsecQuery`. Challenge JSON currently becomes a ban (count +1, empty operator page). The skip the ticket wants belongs on a relay of that JSON, not on the ban path (bans must keep counting).

Call sites of `appsecQuery`: 1 (`handleNextServeHTTP`). Roots searched: `bouncer.go`.

Reproduce: `go test -run TestExploreChallengeDropCount -v .` on dest HEAD (throwaway, then deleted). AppSec 403 `{"action":"challenge",...}` on `/protected` → delta 1, status 403, empty body, `next` 0. Same envelope on `/crowdsec-internal/challenge/submit` → delta 1. Claimed over-count of the submit path: reproduced as two bans. Claimed relay of HTML: not reproduced (dest never writes `user_body_content`).

Outside facts: CrowdSec challenge protocol (in-tree dump; dest has no `knowledge/research/`). Internal paths also return `action: challenge`. Upstream PR 403 point 5 skips `blockedRequests` in `handleAppsecResponseServeHTTP` when the path is under `/crowdsec-internal/challenge/`. This fork's `main` has not merged #343, so that function is absent.

## Decisions

- Chosen: add a minimal AppSec JSON challenge relay on dest (`appsecQuery` returns a parsed envelope; `handleNextServeHTTP` writes it) and do not increment `blockedRequests` when the request path is under `/crowdsec-internal/challenge/`. The challenge page (any other path) increments once. Bans and `pkg/captcha` stay on their existing increment sites.
- Rejected: skip increment inside `handleBanServeHTTP` for that prefix — that would uncount bans, which the ask keeps.
- Rejected: merge full upstream #343 / #373 / #378 / #386 as the vehicle for the skip — extra live-mode, renovate, and HTTP/3 commits.
- Rejected: copy upstream PR 403's patch.
- Live contract: no live contract. Dest has no `openspec/` tree. Do not bootstrap a catalog on `origin/main` for this skip. The regression test is the contract.

## Open questions

- Q: Dest has no challenge relay; can the skip attach without adding one?
  Rank: additive asked — new relay unit this change creates; Desired names a relayed AppSec challenge envelope
  Decision: assumed — add a minimal challenge-JSON relay in `bouncer.go` and skip `blockedRequests` under `/crowdsec-internal/challenge/`; do not merge #343 wholesale
  By: explore

- Q: Dest has no dropped-bytes series; the dump says skip request or bytes.
  Rank: additive asked — dump names bytes; dest `reportMetrics` posts only a request `dropped` item
  Decision: assumed — skip only the request counter dest already has; do not add a bytes series or change the POST shape
  By: explore
